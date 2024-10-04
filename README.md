# Threat Hunting Script

Thess script automates various threat hunting tasks on Linux and Windows systems.

## Overview

The script performs the following key functions:

- Downloads latest IOC files from a server
- Validates IOC file integrity 
- Processes hash and string IOCs against system files
- Audits the system for suspicious files, processes, etc.
- Assembles a report with findings
- Uploads report and supporting files to a remote server
- Adds a cron job to run the script daily

## Usage

The script takes 3 parameters:

```
/opt/security/ioc_ths.sh SERVER_URL UPLOAD_SERVER USER_IDENTITY
```

- `SERVER_URL` - URL of the server hosting the IOC files 
- `UPLOAD_SERVER` - Hostname of server to upload reports to
- `USER_IDENTITY` - Username on upload server to submit reports under

Example:

```
/opt/security/ioc_ths.sh https://ioc.server.com ioc-collector.com john_smith
```

This will download IOCs from ioc.server.com, upload reports to user john_smith on ioc-collector.com.

The cron job added by the script will run it daily with these parameters.

## Output

- Downloaded IOC files in `/opt/security/working`
- Log files in `/opt/security/working` 
- Assembled report `iocreport-*.txt` in `/opt/security/working`
- Archive `*.tgz` and signature `*.tgz.sig` in `/opt/security/working`
- Errors logged to `/opt/security/errors`

After a successful run, the report and supporting files are uploaded to the remote server.

## Dependencies

The script requires the following packages:

- wget
- gpg
- rsync
- ssmtp (for mailing reports)

And the custom validate and strcheck binaries in `/opt/security/bin`.


