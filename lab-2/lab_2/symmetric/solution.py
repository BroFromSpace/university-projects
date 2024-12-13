import base64
import secrets
import typing as t
from pathlib import Path

import typer
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from rich.console import Console
from rich.panel import Panel

console = Console()
app = typer.Typer(
    help="AES-CBC with HMAC symmetric Encryption Utility", no_args_is_help=True
)


class CryptoSolution:
    def generate_key(self, key_size: int = 32) -> bytes:
        """
        Generate a cryptographically secure random encryption key.
        """
        return secrets.token_bytes(key_size)

    def generate_iv(self, iv_size: int = 16) -> bytes:
        """
        Generate a cryptographically secure random initialization vector.
        """
        return secrets.token_bytes(iv_size)

    def encrypt_file(
        self, input_file: Path, output_file: Path, key: bytes, iv: bytes
    ) -> None:
        """
        Encrypt a file using AES-CBC with HMAC for integrity protection.
        """
        with input_file.open("rb") as f:
            plaintext = f.read()

        padder = PKCS7(128).padder()
        padded_data = padder.update(plaintext) + padder.finalize()

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(ciphertext)
        mac = h.finalize()

        with output_file.open("wb") as f:
            output = iv + mac + ciphertext
            f.write(base64.b64encode(output))

    def decrypt_file(self, input_file: Path, output_file: Path, key: bytes) -> None:
        """
        Decrypt a file with AES-CBC and verify its integrity using HMAC.
        """
        with input_file.open("rb") as f:
            encoded_content = f.read()

        content = base64.b64decode(encoded_content)

        iv = content[:16]
        mac = content[16:48]
        ciphertext = content[48:]

        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(ciphertext)
        h.verify(mac)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_data) + unpadder.finalize()

        with output_file.open("wb") as f:
            f.write(plaintext)


@app.command()
def encrypt(
    input_file: t.Annotated[
        Path,
        typer.Option(
            "--input", "-i", exists=True, readable=True, help="Input encrypted file"
        ),
    ],
    output_file: t.Annotated[
        Path, typer.Option("--output", "-o", exists=False, help="Output decrypted file")
    ],
    key_file: t.Annotated[
        Path | None,
        typer.Option(
            "--key",
            "-k",
            exists=False,
            help="File containing the base64 encoded decryption key",
        ),
    ] = None,
):
    """Encrypt a file using AES-CBC with HMAC integrity protection."""
    crypto = CryptoSolution()

    try:
        if key_file:
            with key_file.open("rb") as f:
                key = base64.b64decode(f.read().strip())
        else:
            key = crypto.generate_key()
            b64_key = base64.b64encode(key)
            key_output_file = Path(__file__).parent / "key.txt.key"

            console.print(
                Panel.fit(
                    f"Generated Key: {b64_key}\nKey stored in {key_output_file}",
                    title="[bold blue]New Encryption Key",
                    title_align="left",
                    border_style="blue",
                )
            )

            with key_output_file.open("wb") as f:
                f.write(b64_key)

        iv = crypto.generate_iv()
        console.print(
            Panel.fit(
                f"Initialization Vector: {base64.b64encode(iv)}",
                title="[bold blue]IV Generated",
                title_align="left",
                border_style="blue",
            )
        )

        crypto.encrypt_file(input_file, output_file, key, iv)

        console.print(
            Panel.fit(
                f"Input File: {input_file}\nOutput File: {output_file}",
                title="[bold green]Encryption Successful",
                border_style="green",
            )
        )
    except Exception as e:
        console.print(
            Panel.fit(
                f"[red]Error:[/] {e}",
                title="[bold red]Encryption Failed",
                border_style="red",
            )
        )
        raise typer.Exit(1)


@app.command()
def decrypt(
    input_file: t.Annotated[
        Path,
        typer.Option(
            ..., "--input", "-i", exists=True, readable=True, help="Input encrypted file"
        ),
    ],
    output_file: t.Annotated[
        Path,
        typer.Option(..., "--output", "-o", exists=False, help="Output decrypted file"),
    ],
    key_file: t.Annotated[
        Path,
        typer.Option(
            ...,
            "--key",
            "-k",
            exists=True,
            readable=True,
            help="File containing the base64 encoded decryption key",
        ),
    ],
):
    """Decrypt an encrypted file using the provided key."""
    crypto = CryptoSolution()

    try:
        with key_file.open("rb") as f:
            key = base64.b64decode(f.read().strip())

        crypto.decrypt_file(input_file, output_file, key)
        console.print(
            Panel.fit(
                f"Input File: {input_file}\nOutput File: {output_file}",
                title="[bold green]Decryption Successful",
                border_style="green",
            )
        )
    except Exception as e:
        console.print(
            Panel.fit(
                f"[red]Error:[/] {e}",
                title="[bold red]Decryption Failed",
                border_style="red",
            )
        )
        raise typer.Exit(1)
