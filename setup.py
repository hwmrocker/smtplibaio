from distutils.core import setup
setup(
    name='smtplibaio',
    packages=[
        'smtplibaio',
    ],

    version='2.0.2',
    description='An async version of smtplib',

    author='Olaf Gladis',
    author_email='github@gladis.org',

    url='https://github.com/hwmrocker/smtplibaio',
    download_url='https://github.com/hwmrocker/smtplibaio/tarball/2.0.2',

    keywords=['smtplib', 'asyncio'],

    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3 :: Only",
        'Programming Language :: Python :: 3.5',
        "Topic :: Communications :: Email",
    ],
)
