from distutils.core import setup
setup(
    name='smtplibaio',
    packages=[
        'smtplibaio',
    ],

    version='2.1.0',
    description='An async version of smtplib',

    author='Olaf Gladis',
    author_email='github@gladis.org',

    url='https://github.com/hwmrocker/smtplibaio',
    download_url='https://github.com/hwmrocker/smtplibaio/tarball/2.1.0',

    keywords=['smtplib', 'asyncio'],

    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3 :: Only",
        'Programming Language :: Python :: 3.5',
        "Topic :: Communications :: Email",
    ],

    setup_requires=[
        'aioopenssl',
    ],
)
