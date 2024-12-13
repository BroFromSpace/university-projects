import base64
import typing as t
from pathlib import Path

import typer
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from rich.console import Console
from rich.panel import Panel

console = Console()
app = typer.Typer(
    help="RSA Asymmetric Encryption and Digital Signature Utility", no_args_is_help=True
)


class RSACryptoSolution:
    def generate_key_pair(
        self, key_size: int = 2048
    ) -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """
        Generate an RSA key pair.
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=key_size, backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def save_private_key(
        self, private_key: rsa.RSAPrivateKey, output_file: Path
    ) -> None:
        """
        Save private key to a file in PEM format.
        """
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with output_file.open("wb") as f:
            f.write(pem)

    def save_public_key(self, public_key: rsa.RSAPublicKey, output_file: Path) -> None:
        """
        Save public key to a file in PEM format.
        """
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        with output_file.open("wb") as f:
            f.write(pem)

    def load_private_key(self, key_file: Path) -> rsa.RSAPrivateKey:
        """
        Load private key from a PEM file.
        """
        with key_file.open("rb") as f:
            return serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )  # type: ignore

    def load_public_key(self, key_file: Path) -> rsa.RSAPublicKey:
        """
        Load public key from a PEM file.
        """
        with key_file.open("rb") as f:
            return serialization.load_pem_public_key(f.read(), backend=default_backend())  # type: ignore

    def encrypt_file(
        self, input_file: Path, output_file: Path, public_key: rsa.RSAPublicKey
    ) -> None:
        """
        Encrypt a file using RSA public key encryption.
        """
        with input_file.open("rb") as f:
            plaintext = f.read()

        ciphertext = public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        with output_file.open("wb") as f:
            f.write(base64.b64encode(ciphertext))

    def decrypt_file(
        self, input_file: Path, output_file: Path, private_key: rsa.RSAPrivateKey
    ) -> None:
        """
        Decrypt a file using RSA private key decryption.
        """
        with input_file.open("rb") as f:
            encoded_content = f.read()

        ciphertext = base64.b64decode(encoded_content)

        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        with output_file.open("wb") as f:
            f.write(plaintext)

    def create_signature(
        self, input_file: Path, private_key: rsa.RSAPrivateKey
    ) -> bytes:
        """
        Create a digital signature for a file using the private key.
        """
        with input_file.open("rb") as f:
            data = f.read()

        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
        return signature

    def verify_signature(
        self, input_file: Path, signature: bytes, public_key: rsa.RSAPublicKey
    ) -> bool:
        """
        Verify the digital signature of a file using the public key.
        """
        with input_file.open("rb") as f:
            data = f.read()

        try:
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256(),
            )
            return True
        except Exception:
            return False


@app.command()
def generate_keys(
    private_key_output: t.Annotated[
        Path | None,
        typer.Option(
            "--private", "-pr", exists=False, help="Output path for private key"
        ),
    ] = None,
    public_key_output: t.Annotated[
        Path | None,
        typer.Option("--public", "-pu", exists=False, help="Output path for public key"),
    ] = None,
    key_size: t.Annotated[
        int, typer.Option("--size", "-s", help="RSA key size in bits")
    ] = 2048,
):
    """Generate an RSA key pair."""
    crypto = RSACryptoSolution()

    try:
        private_key, public_key = crypto.generate_key_pair(key_size)

        if not private_key_output:
            private_key_output = Path(__file__).parent / "private.pem"
        if not public_key_output:
            public_key_output = Path(__file__).parent / "public.pem"

        crypto.save_private_key(private_key, private_key_output)
        crypto.save_public_key(public_key, public_key_output)

        console.print(
            Panel.fit(
                f"Private Key: {private_key_output}\nPublic Key: {public_key_output}",
                title="[bold green]Key Pair Generated Successfully",
                border_style="green",
            )
        )
    except Exception as e:
        console.print(
            Panel.fit(
                f"[red]Error:[/] {e}",
                title="[bold red]Key Generation Failed",
                border_style="red",
            )
        )
        raise typer.Exit(1)


@app.command()
def encrypt(
    input_file: t.Annotated[
        Path,
        typer.Option(
            "--input", "-i", exists=True, readable=True, help="Input file to encrypt"
        ),
    ],
    output_file: t.Annotated[
        Path, typer.Option("--output", "-o", exists=False, help="Output encrypted file")
    ],
    public_key_file: t.Annotated[
        Path,
        typer.Option(
            "--key", "-k", exists=True, readable=True, help="Public key for encryption"
        ),
    ],
):
    """Encrypt a file using RSA public key."""
    crypto = RSACryptoSolution()

    try:
        public_key = crypto.load_public_key(public_key_file)
        crypto.encrypt_file(input_file, output_file, public_key)

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
            "--input", "-i", exists=True, readable=True, help="Input encrypted file"
        ),
    ],
    output_file: t.Annotated[
        Path, typer.Option("--output", "-o", exists=False, help="Output decrypted file")
    ],
    private_key_file: t.Annotated[
        Path,
        typer.Option(
            "--key", "-k", exists=True, readable=True, help="Private key for decryption"
        ),
    ],
):
    """Decrypt an encrypted file using RSA private key."""
    crypto = RSACryptoSolution()

    try:
        private_key = crypto.load_private_key(private_key_file)
        crypto.decrypt_file(input_file, output_file, private_key)

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


@app.command()
def sign(
    input_file: t.Annotated[
        Path,
        typer.Option(
            "--input", "-i", exists=True, readable=True, help="Input file to sign"
        ),
    ],
    private_key_file: t.Annotated[
        Path,
        typer.Option(
            "--key", "-k", exists=True, readable=True, help="Private key for signing"
        ),
    ],
    signature_file: t.Annotated[
        Path,
        typer.Option("--signature", "-s", exists=False, help="Output signature file"),
    ],
):
    """Create a digital signature for a file."""
    crypto = RSACryptoSolution()

    try:
        private_key = crypto.load_private_key(private_key_file)
        signature = crypto.create_signature(input_file, private_key)

        with signature_file.open("wb") as f:
            f.write(base64.b64encode(signature))

        console.print(
            Panel.fit(
                f"Input File: {input_file}\nSignature File: {signature_file}",
                title="[bold green]Signature Created Successfully",
                border_style="green",
            )
        )
    except Exception as e:
        console.print(
            Panel.fit(
                f"[red]Error:[/] {e}",
                title="[bold red]Signature Creation Failed",
                border_style="red",
            )
        )
        raise typer.Exit(1)


@app.command()
def verify(
    input_file: t.Annotated[
        Path,
        typer.Option(
            "--input", "-i", exists=True, readable=True, help="Input file to verify"
        ),
    ],
    signature_file: t.Annotated[
        Path,
        typer.Option(
            "--signature", "-s", exists=True, readable=True, help="Signature file"
        ),
    ],
    public_key_file: t.Annotated[
        Path,
        typer.Option(
            "--key", "-k", exists=True, readable=True, help="Public key for verification"
        ),
    ],
):
    """Verify the digital signature of a file."""
    crypto = RSACryptoSolution()

    try:
        with signature_file.open("rb") as f:
            signature = base64.b64decode(f.read())

        public_key = crypto.load_public_key(public_key_file)
        is_valid = crypto.verify_signature(input_file, signature, public_key)

        if is_valid:
            console.print(
                Panel.fit(
                    f"Input File: {input_file}\nSignature: Valid",
                    title="[bold green]Signature Verification Successful",
                    border_style="green",
                )
            )
        else:
            console.print(
                Panel.fit(
                    f"Input File: {input_file}\nSignature: Invalid",
                    title="[bold red]Signature Verification Failed",
                    border_style="red",
                )
            )
    except Exception as e:
        console.print(
            Panel.fit(
                f"[red]Error:[/] {e}",
                title="[bold red]Signature Verification Failed",
                border_style="red",
            )
        )
        raise typer.Exit(1)
