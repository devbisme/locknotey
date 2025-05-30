#!/usr/bin/env python

# MIT license. Copyright 2021 by Dave Vandenbout.

import argparse
import logging
import sys
import base64
import os
import re
import subprocess
from tempfile import NamedTemporaryFile
import time

import FreeSimpleGUI as sg
from cryptography.fernet import Fernet, InvalidToken

from locknotey import __version__

__author__ = "Dave Vandenbout"
__copyright__ = "Dave Vandenbout"
__license__ = "MIT"

_logger = logging.getLogger(__name__)


password = ""
start_data = '"""\nSTART_OF_ENCRYPTED_DATA\n'
end_data = 'END_OF_ENCRYPTED_DATA\n"""\n'
gui_font = "Helvetica 15"
# sg.theme('DarkAmber')


class Crypto(Fernet):
    """Subclass of Fernet that creates a key from a user-supplied password."""

    def __init__(self, password):
        pwd_len = len(password)
        password = (((128 + pwd_len - 1) // pwd_len) * password)[:32].encode()
        password = base64.urlsafe_b64encode(password)
        super().__init__(password)

    def encrypt(self, clear_text):
        """Return encrypted string."""
        return super().encrypt(clear_text.encode()).decode()

    def decrypt(self, cipher_text):
        """Return decrypted string."""
        return super().decrypt(cipher_text.encode()).decode()


def show_msg(msg):
    """Show message in dialog box with OK button to dismiss."""

    event, values = sg.Window(
        "Locknote", [[sg.Text(msg, font=gui_font)], [sg.Submit("OK", font=gui_font)],]
    ).read(close=True)


def get_decrypt_password():
    """Open dialog box and return user-supplied password for decrypting."""

    global password
    while True:
        event, values = sg.Window(
            "Locknote - Enter Password",
            [
                [
                    sg.Text("Password:", font=gui_font),
                    sg.InputText(password_char="*", font=gui_font),
                ],
                [sg.Submit("OK", font=gui_font), sg.Cancel("Cancel", font=gui_font)],
            ],
        ).read(close=True)

        # Abort the entire program if the user cancels password entry.
        if event in (sg.WIN_CLOSED, "Cancel"):
            sys.exit(0)

        # Keep trying until the user enters something.
        password = values[0]
        if password:
            return password
        show_msg("Try harder.")


def get_encrypt_password():
    """Open dialog box and return user-supplied password for encrypting."""

    global password

    while True:
        # The dialog has two boxes to enter and confirm the password.
        event, values = sg.Window(
            "Enter Encryption Password",
            [
                [
                    sg.Text("Password:", font=gui_font),
                    sg.InputText(
                        default_text=password, password_char="*", font=gui_font
                    ),
                ],
                [
                    sg.Text("Re-enter Password:", font=gui_font),
                    sg.InputText(
                        default_text=password, password_char="*", font=gui_font
                    ),
                ],
                [sg.Submit("OK", font=gui_font), sg.Cancel("Cancel", font=gui_font)],
            ],
        ).read(close=True)

        if event in (sg.WIN_CLOSED, "Cancel"):
            # Abort the entire program if the user cancels password entry.
            sys.exit(0)
        elif values[0] != values[1]:
            # Keep trying until both passwords match.
            show_msg("Passwords don't match! Try again.")
        else:
            # Passwords match, so return the password.
            password = values[0]
            return password


def extract_program_text(filename):
    """Extract the program code from this script that precedes the encrypted data."""

    with open(filename) as fp:
        file_contents = "".join(fp.readlines())

    try:
        # Return program code preceding the delimiter that marks the start of encrypted data.
        program_text = re.search(rf"(?s)(.*){start_data}", file_contents).group(1)
    except AttributeError:
        # Delimiter not found, so the program code is just the entire contents of the file.
        program_text = file_contents
    return program_text


def clear_data(filename):
    """Clear any encrypted data at the end of this file."""

    # Get program code.
    program_text = extract_program_text(filename)

    # Overwrite this file with the program code and an empty encrypted data section.
    with open(filename, "w") as fp:
        fp.write(program_text)
        fp.write(f"{start_data}{end_data}")


def extract_encrypted_data(filename):
    """Return the encrypted data at the end of this file."""

    with open(filename) as fp:
        file_contents = "".join(fp.readlines())

    try:
        # Return the ciphertext within the delimiters at the end of this file.
        return re.search(rf"(?s){start_data}(.*){end_data}", file_contents).group(1)
    except AttributeError:
        # No ciphertext found, so clear the end of the file and return an empty string.
        clear_data(filename)
        return ""


def extract_user_data(filename):
    """Decrypt the ciphertext from the end of this file and return it."""

    # Get the ciphertext.
    data = extract_encrypted_data(filename)

    if data:
        # Get a password from the user.
        password = get_decrypt_password()

        try:
            # Return the cleartext if it was decrypted successfully.
            return Crypto(password).decrypt(data)
        except InvalidToken:
            # Abort if an incorrect password was given.
            show_msg("Incorrect password!")
            sys.exit(0)

    # Return an empty string if there is no ciphertext. This is used when
    # starting from an empty initial file.
    return ""


def edit_user_data(editor_cmd, filename):
    """Decrypt the ciphertext and open it in an editor. Return the data after the editor closes."""

    # Decrypt ciphertext to get cleartext.
    user_data = extract_user_data(filename)

    # Store cleartext in a temporary file and pass it to an external editor.
    edit_file = NamedTemporaryFile(
        dir=".", mode="w", prefix="LN_", suffix=".txt", delete=False
    )
    edit_file_name = edit_file.name
    editor = editor_cmd.split()  # Editor command may have space-separated arguments.
    editor.append(edit_file_name)  # Attach cleartext file name to editor command.
    edit_file.write(user_data)  # Store cleartext in file and close it.
    edit_file.close()
    p = subprocess.Popen(editor)  # Run editor with arguments in a subprocess.

    # Poll the process to detect when the editor has been closed.
    INITIAL_DELAY = 2  # Give the editor time to open the file.
    delay = INITIAL_DELAY
    while p.poll() == None:
        time.sleep(delay)
        if delay == INITIAL_DELAY:
            # Once the editor has had time to open the file,
            # overwrite the cleartext with some random stuff.
            # Don't just erase it because we want a way to check
            # if the editor made some changes to the file which
            # may mean erasing everything.
            rand_data = Fernet.generate_key().decode()
            with open(edit_file_name, "w") as fp:
                fp.write(rand_data)

            # Poll more often once the editor has gotten started.
            delay = 0.1

    try:
        # Get the new cleartext from the edited file.
        with open(edit_file_name) as fp:
            new_user_data = "".join(fp.readlines())
        os.remove(edit_file_name)  # Remove the edited cleartext.
    except FileNotFoundError:
        # The edited cleartext file is missing, so abort without changing anything.
        sys.exit(0)

    if new_user_data == rand_data or new_user_data == user_data:
        # If the cleartext is just the random stuff we stored, then
        # the editor didn't save anything. Or the new cleartext is the
        # same as the original. In either case, just return the
        # original cleartext.
        return user_data

    # The edited cleartext has changed, so return it.
    return new_user_data


def encrypt_user_data(user_data):
    """Encrypt the cleartext with a user-supplied password and return the ciphertext."""

    while True:
        password = get_encrypt_password()
        if password:
            return Crypto(password).encrypt(user_data)
        show_msg("Try harder.")  # Keep trying to get a password.


def store_user_data(user_data, filename):
    """Encrypt the cleartext and store it at the end of this file."""

    # Get the program code and the ciphertext to append to it.
    program_text = extract_program_text(filename)
    data = encrypt_user_data(user_data)

    # Overwrite this file with the program code and the ciphertext.
    with open(filename, "w") as fp:
        fp.write(program_text)
        fp.write(f"{start_data}{data}{end_data}")


def parse_args():
    """Parse command line parameters."""

    parser = argparse.ArgumentParser(
        description="Locknotey for storing/recalling encrypted information."
    )
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version="locknotey {ver}".format(ver=__version__),
    )
    parser.add_argument(
        "-n", "--new", metavar="FILE", default=None, help="Make an empty local copy of locknotey and exit."
    )
    parser.add_argument(
        "-u", "--update", metavar="FILE", default=None, help="Update programming code in a locknotey file."
    )
    parser.add_argument(
        "-e",
        "--editor",
        metavar="EDITOR_CMD",
        default=os.environ.get("EDITOR"),
        help="Specify the editor command line to use.",
    )

    return parser.parse_args()


def main():
    args = parse_args()

    if args.new:
        # Create an empty locknotey file and then quit.
        with open(args.new, "w") as fp:
            fp.write(extract_program_text(__file__))
            sys.exit(0)

    if args.update:
        # Update the program code in an existing locknotey file and then quit.
        data = extract_encrypted_data(args.update)
        code = extract_program_text(__file__)
        with open(args.update, "w") as fp:
            fp.write(code)
            fp.write(f"{start_data}{data}{end_data}")
        sys.exit(0)

    # Setup editor command.
    editor_cmd = args.editor

    # Decrypt, edit and restore the user data.
    store_user_data(edit_user_data(editor_cmd, __file__), __file__)


if __name__ == "__main__":
    main()
