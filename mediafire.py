#!/usr/bin/env python3

import hashlib
import os
import threading
import time
from re import findall
from tkinter import (
    Tk,
    Label,
    Entry,
    Button,
    filedialog,
    IntVar,
    messagebox,
    StringVar,
    ttk,
)
from gazpacho import Soup
from requests import get, head
from argparse import ArgumentParser
from gazpacho.utils import HTTPError


class bcolors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


NON_ALPHANUM_FILE_OR_FOLDER_NAME_CHARACTERS = "-_. "
NON_ALPHANUM_FILE_OR_FOLDER_NAME_CHARACTER_REPLACEMENT = "-"


def hash_file(filename: str) -> str:
    h = hashlib.sha256()
    with open(filename, "rb") as file:
        chunk = 0
        while chunk != b"":
            chunk = file.read(1024)
            h.update(chunk)
    return h.hexdigest()


def normalize_file_or_folder_name(filename: str) -> str:
    return "".join(
        [
            (
                char
                if (
                    char.isalnum()
                    or char in NON_ALPHANUM_FILE_OR_FOLDER_NAME_CHARACTERS
                )
                else NON_ALPHANUM_FILE_OR_FOLDER_NAME_CHARACTER_REPLACEMENT
            )
            for char in filename
        ]
    )


def print_error(link: str):
    print(
        f"{bcolors.FAIL}Deleted file or Dangerous File Blocked\n"
        f"{bcolors.WARNING}Take a look if you want to be sure: {link}{bcolors.ENDC}"
    )


def main(url, output, threads, progress_callback, stop_event, pause_event):
    folder_or_file = findall(
        r"mediafire\.com/(folder|file|file_premium)\/([a-zA-Z0-9]+)", url
    )
    if not folder_or_file:
        print(f"{bcolors.FAIL}Invalid link{bcolors.ENDC}")
        return

    t, key = folder_or_file[0]

    if t in {"file", "file_premium"}:
        get_file(key, output, progress_callback, stop_event, pause_event)
    elif t == "folder":
        get_folders(
            key, output, threads, progress_callback, stop_event, pause_event, first=True
        )
    else:
        print(f"{bcolors.FAIL}Invalid link{bcolors.ENDC}")
        return

    print(f"{bcolors.OKGREEN}{bcolors.BOLD}All downloads completed{bcolors.ENDC}")


def get_files_or_folders_api_endpoint(
    filefolder: str, folder_key: str, chunk: int = 1, info: bool = False
) -> str:
    return (
        f"https://www.mediafire.com/api/1.4/folder"
        f"/{'get_info' if info else 'get_content'}.php?r=utga&content_type={filefolder}"
        f"&filter=all&order_by=name&order_direction=asc&chunk={chunk}"
        f"&version=1.5&folder_key={folder_key}&response_format=json"
    )


def get_info_endpoint(file_key: str) -> str:
    return f"https://www.mediafire.com/api/file/get_info.php?quick_key={file_key}&response_format=json"


def get_folders(
    folder_key: str,
    folder_name: str,
    threads_num: int,
    progress_callback,
    stop_event,
    pause_event,
    first: bool = False,
) -> None:
    if first:
        folder_name = os.path.join(
            folder_name,
            normalize_file_or_folder_name(
                get(
                    get_files_or_folders_api_endpoint("folder", folder_key, info=True)
                ).json()["response"]["folder_info"]["name"]
            ),
        )
    if not os.path.exists(folder_name):
        os.makedirs(folder_name)
    os.chdir(folder_name)
    download_folder(folder_key, threads_num, progress_callback, stop_event, pause_event)
    folder_content = get(
        get_files_or_folders_api_endpoint("folders", folder_key)
    ).json()["response"]["folder_content"]
    if "folders" in folder_content:
        for folder in folder_content["folders"]:
            get_folders(
                folder["folderkey"],
                folder["name"],
                threads_num,
                progress_callback,
                stop_event,
                pause_event,
            )
            os.chdir("..")


def download_folder(
    folder_key: str, threads_num: int, progress_callback, stop_event, pause_event
) -> None:
    data = []
    chunk = 1
    more_chunks = True
    try:
        while more_chunks:
            r_json = get(
                get_files_or_folders_api_endpoint("files", folder_key, chunk=chunk)
            ).json()
            more_chunks = r_json["response"]["folder_content"]["more_chunks"] == "yes"
            data += r_json["response"]["folder_content"]["files"]
            chunk += 1
    except KeyError:
        print("Invalid link")
        return

    event = threading.Event()
    threadLimiter = threading.BoundedSemaphore(threads_num)
    total_threads = []

    for file in data:
        total_threads.append(
            threading.Thread(
                target=download_file,
                args=(
                    file,
                    event,
                    threadLimiter,
                    progress_callback,
                    stop_event,
                    pause_event,
                ),
            )
        )
    for thread in total_threads:
        thread.start()

    try:
        while True:
            if all(not t.is_alive() for t in total_threads):
                break
            time.sleep(0.01)
    except KeyboardInterrupt:
        print(f"{bcolors.WARNING}Closing all threads{bcolors.ENDC}")
        event.set()
        for thread in total_threads:
            thread.join()
        print(f"{bcolors.WARNING}{bcolors.BOLD}Download interrupted{bcolors.ENDC}")


def get_file(
    key: str,
    output_path: str = None,
    progress_callback=None,
    stop_event=None,
    pause_event=None,
) -> None:
    file_data = get(get_info_endpoint(key)).json()["response"]["file_info"]
    if output_path:
        os.chdir(output_path)
    download_file(
        file_data,
        progress_callback=progress_callback,
        stop_event=stop_event,
        pause_event=pause_event,
    )


def download_file(
    file: dict,
    event: threading.Event = None,
    limiter: threading.BoundedSemaphore = None,
    progress_callback=None,
    stop_event=None,
    pause_event=None,
) -> None:
    if limiter:
        limiter.acquire()
    download_link = file["links"]["normal_download"]
    filename = normalize_file_or_folder_name(file["filename"])
    if os.path.exists(filename):
        if hash_file(filename) == file["hash"]:
            print(f"{bcolors.WARNING}{filename}{bcolors.ENDC} already exists, skipping")
            if limiter:
                limiter.release()
            return
        else:
            print(
                f"{bcolors.WARNING}{filename}{bcolors.ENDC} already exists but corrupted, downloading again"
            )
    print(f"{bcolors.OKBLUE}Downloading {filename}{bcolors.ENDC}")
    if event and event.is_set():
        if limiter:
            limiter.release()
        return
    try:
        if head(download_link).headers.get("content-encoding") == "gzip":
            html = get(download_link).text
            soup = Soup(html)
            download_link = (
                soup.find("div", {"class": "download_link"})
                .find("a", {"class": "input popsok"})
                .attrs["href"]
            )
    except Exception:
        print_error(download_link)
        if limiter:
            limiter.release()
        return
    with get(download_link, stream=True) as r:
        r.raise_for_status()
        total_length = int(r.headers.get("content-length", 0))
        with open(filename, "wb") as f:
            dl = 0
            for chunk in r.iter_content(chunk_size=4096):
                if event and event.is_set():
                    break
                if stop_event and stop_event.is_set():
                    os.remove(filename)
                    print(
                        f"{bcolors.WARNING}Download stopped for {filename}{bcolors.ENDC}"
                    )
                    if limiter:
                        limiter.release()
                    return
                if pause_event and pause_event.is_set():
                    while pause_event.is_set():
                        time.sleep(0.1)
                if chunk:
                    f.write(chunk)
                    dl += len(chunk)
                    if progress_callback:
                        progress_callback(filename, dl, total_length)
    if event and event.is_set():
        os.remove(filename)
        print(f"{bcolors.WARNING}Partially downloaded {filename} deleted{bcolors.ENDC}")
        if limiter:
            limiter.release()
        return
    print(f"{bcolors.OKGREEN}{filename}{bcolors.ENDC} downloaded")
    if limiter:
        limiter.release()


class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Mediafire Bulk Downloader")

        self.url_label = Label(root, text="Mediafire URL:")
        self.url_label.grid(row=0, column=0, padx=10, pady=10)
        self.url_entry = Entry(root, width=50)
        self.url_entry.grid(row=0, column=1, padx=10, pady=10)

        self.output_label = Label(root, text="Output Directory:")
        self.output_label.grid(row=1, column=0, padx=10, pady=10)
        self.output_entry = Entry(root, width=50)
        self.output_entry.grid(row=1, column=1, padx=10, pady=10)
        self.browse_button = Button(root, text="Browse", command=self.browse_directory)
        self.browse_button.grid(row=1, column=2, padx=10, pady=10)

        self.threads_label = Label(root, text="Number of Threads:")
        self.threads_label.grid(row=2, column=0, padx=10, pady=10)
        self.threads_entry = Entry(root, width=5)
        self.threads_entry.grid(row=2, column=1, padx=10, pady=10)
        self.threads_entry.insert(0, "10")

        self.start_button = Button(
            root, text="Start Download", command=self.start_download
        )
        self.start_button.grid(row=3, column=0, columnspan=3, padx=10, pady=10)

        self.progress_label = Label(root, text="Download Progress:")
        self.progress_label.grid(row=4, column=0, padx=10, pady=10)
        self.progress_bar = ttk.Progressbar(root, length=400, mode="determinate")
        self.progress_bar.grid(row=4, column=1, columnspan=2, padx=10, pady=10)

        self.pause_button = Button(
            root, text="Pause", command=self.pause_download, state="disabled"
        )
        self.pause_button.grid(row=5, column=0, padx=10, pady=10)
        self.resume_button = Button(
            root, text="Resume", command=self.resume_download, state="disabled"
        )
        self.resume_button.grid(row=5, column=1, padx=10, pady=10)
        self.stop_button = Button(
            root, text="Stop", command=self.stop_download, state="disabled"
        )
        self.stop_button.grid(row=5, column=2, padx=10, pady=10)

        self.stop_event = threading.Event()
        self.pause_event = threading.Event()

    def browse_directory(self):
        directory = filedialog.askdirectory()
        if directory:
            self.output_entry.delete(0, "end")
            self.output_entry.insert(0, directory)

    def update_progress(self, filename, downloaded, total_length):
        progress = downloaded / total_length * 100
        self.progress_bar["value"] = progress
        self.root.update_idletasks()

    def start_download(self):
        url = self.url_entry.get()
        output = self.output_entry.get()
        try:
            threads = int(self.threads_entry.get())
        except ValueError:
            messagebox.showerror(
                "Invalid input", "Number of threads must be an integer."
            )
            return

        if not url or not output or not threads:
            messagebox.showerror("Invalid input", "All fields must be filled.")
            return

        self.pause_button.config(state="normal")
        self.stop_button.config(state="normal")

        self.download_thread = threading.Thread(
            target=main,
            args=(
                url,
                output,
                threads,
                self.update_progress,
                self.stop_event,
                self.pause_event,
            ),
        )
        self.download_thread.start()

    def pause_download(self):
        self.pause_event.set()
        self.pause_button.config(state="disabled")
        self.resume_button.config(state="normal")

    def resume_download(self):
        self.pause_event.clear()
        self.pause_button.config(state="normal")
        self.resume_button.config(state="disabled")

    def stop_download(self):
        self.stop_event.set()
        self.download_thread.join()
        self.stop_event.clear()
        self.pause_event.clear()
        self.progress_bar["value"] = 0
        self.pause_button.config(state="disabled")
        self.resume_button.config(state="disabled")
        self.stop_button.config(state="disabled")


if __name__ == "__main__":
    root = Tk(className="Bulk Downloader")
    app = App(root)
    root.mainloop()
