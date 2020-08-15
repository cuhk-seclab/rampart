# Rampart

Rampart is a system for protecting the back end of web applications from CPU-exhaustion Denial-of-Service (DoS) attacks. It leverages context-aware function-level program profiling and statistical execution models to help defend against such attacks. Rampart is very lightweight and introduces a modest runtime overhead.

It has been implemented for PHP applications as an extension to the PHP Zend engine. The implementation is based on the [Tideways PHP Profiler Extension](https://github.com/tideways/php-xhprof-extension) version 4.1.3.

You can find more information about Rampart in our [USENIX Security 2018 research paper](https://seclab.cse.cuhk.edu.hk/papers/sec18_rampart.pdf). The BibTeX format file is provided with the source code.

## Requirements

- PHP 5.6 or 7.0
- php-dev, libsqlite3-dev packages
- numpy, sqlite3 for Python
- Tested with Linux amd64 architecture

## Installation

Build rampart from source:

```shell
phpize
./configure
make
sudo make install
```

Create necessary directories for rampart:

```shell
sudo mkdir -p /var/log/rampart/logs
sudo mkdir -p /var/log/rampart/db
sudo chown www-data:www-data /var/log/rampart/logs
sudo chown www-data:www-data /var/log/rampart/db
```
You can modify the source code to use other locations. Please ensure that your web server has the write permission to access the directories.

Afterwards you need to enable the extension in your php.ini (e.g., /etc/php/7.0/apache2/php.ini) and then restart Apache:

    extension=rampart.so

## Run

Start the Python script for managing profiling data and filter rules.
```shell
python stat_db_mgr.py
```

Rampart can then enforce the defense after receiving at least *five legitimate requests per PHP script* as a training step. You are recommended to use test inputs with a high code coverage for a better protection.

## Parameters

There are many parameters that control how Rampart works. They can be modified in the `rampart_setting.h` file. In particular, Rampart terminates PHP instances serving suspicious requests only when the system average CPU usage is greater than `CPU_USAGE_UPPER_THRESHOLD`, which is set to 50% by default. Please read the paper for more details.

## Copyright Information

Copyright © 2018 The Chinese University of Hong Kong

## License

Rampart is licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0).
You can find a copy in the "LICENSE" file.

See the "NOTICE" file for information on the attribution notices. 

## Creator

[Wei Meng](https://www.cse.cuhk.edu.hk/~wei/) <wei@cse.cuhk.edu.hk>
