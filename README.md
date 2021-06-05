# locknotey

Simple script that stores encrypted data within itself and allows you to modify it using any editor.


## Description

I was a long-time user of [LockNote](https://sourceforge.net/projects/locknote/), but there was no
native version of it when I switched to linux. This is my attempt to re-create that functionality
in a Python script.

## Installation

Install `locknotey` as follows:

```bash
pip install locknotey
```

## Usage

Use `locknotey` as follows:

1. Make a separate copy of the `locknotey` script file for anything you want to store securely using the command `locknotey --new /path/to/my/note_file`. For example, I store all my online account information in a copy called `passwords`. You can store this script file anywhere you like.
2. Execute the new script file. (I assume you have Python and the requisite supporting modules since you installed this using `pip`.)
3. A blank editor window should appear. The editor that's used is specified by your `EDITOR` environment variable. (You could also use the option `-e "editor_cmd arg1 arg2..."` to select another editor.)
4. Put whatever you want into the editor, for example login names/passwords or names of criminal associates.
5. Save and quit the editor. Then you will be asked for a password to encrypt the text after which the ciphertext will be stored within the script file.
6. To see what you've stored, execute the script file again. You'll be asked for a password after which the encrypted text will be decrypted and displayed in an editor window. From there you can search and/or modify the text and store it back into the script file with the same or a new password.

## FAQ

### Is it secure?

The file itself is as secure as the Python `cryptography` module will allow. Probably the weakest point is when the unencrypted text is being handled in the editor. Somebody who had access to your system might be able to get the clear text from the editor process. So don't use `locknotey` to store your nuclear launch codes.

### Will it accidentally eat all my passwords?

It's alpha so it might. I still keep a copy of my passwords in another encrypted file. I'll trust it more once I've gotten to a higher release than 0.1.
