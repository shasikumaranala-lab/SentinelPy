def print_banner(name: str, version: str) -> None:
    print("=" * 60)
    print(f"{name} v{version}".center(60))
    print("Security Log Analysis & Detection Tool".center(60))
    print("=" * 60)
    print()


def print_configuration(
    input_file: str,
    source: str,
    report_format: str,
    output_file: str,
) -> None:

    print(f"Input File     : {input_file}")
    print(f"Log Source     : {source}")
    print(f"Report Format  : {report_format}")
    print(f"Output File    : {output_file}")
    print()

    print("-" * 60)
    print()

def print_progress(step: int, total: int, message: str):

    print(f"[{step}/{total}] {message}")

def print_success(output_path: str):

    print()

    print("-" * 60)

    print()

    print("Analysis Completed Successfully")

    print()

    print(f"Report Generated:")

    print(output_path)

    print()

    print("=" * 60)