from setuptools import setup, find_packages

setup(
    name="mediafire_bulk_downloader",
    version="0.1",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "requests",
        "beautifulsoup4",
        "tqdm",
        "click",
        "colorama",
        "fake-useragent",
    ],
    entry_points={
        "console_scripts": [
            "mediafire_bulk_downloader=mediafire_bulk_downloader.__main__:main"
        ]
    },
    url="https://github.com/NicKoehler/mediafire_bulk_downloader",
    license="MIT",
    author="Your Name",
    author_email="your@email.com",
    description="A tool for downloading files from MediaFire in bulk",
    long_description="""A tool for downloading files from MediaFire in bulk. For more information, visit the GitHub repository: https://github.com/NicKoehler/mediafire_bulk_downloader""",
    long_description_content_type="text/markdown",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
