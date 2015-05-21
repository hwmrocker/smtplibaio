from distutils.core import setup
setup(
    name='smtplibaio',
    packages=['smtplibaio'],  # this must be the same as the name above
    version='1.0',
    description='A ansync version of smtplib',
    author='Olaf Gladis',
    author_email='github@gladis.org',
    url='https://github.com/hwmrocker/smtplibaio',  # use the URL to the github repo
    download_url='https://github.com/hwmrocker/smtplibaio/tarball/1.0',  # I'll explain this in a second
    keywords=['smtplib', 'asyncio'],  # arbitrary keywords
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3 :: Only",
        "Topic :: Communications :: Email",
    ],
)
