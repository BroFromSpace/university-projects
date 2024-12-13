from typer import Typer

from lab_2 import asymmetric, symmetric


def main() -> None:
    app = Typer(
        help="Secure File Encryption and Decryption Utilities", no_args_is_help=True
    )
    app.add_typer(symmetric.app, name="symmetric")
    app.add_typer(asymmetric.app, name="asymmetric")

    app()


if __name__ == "__main__":
    main()
