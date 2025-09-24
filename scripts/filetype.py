import argparse
import pyfsig

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Show file type.")
    parser.add_argument("filename", help="Path to the file to be processed")
    args = parser.parse_args()
    file_path = args.filename

    try:
        with open(file_path,'rb') as file:
            file_header = file.read(2)
            print(file_header)
        matches = find_matches_for_file_header(header=file_header)
        print(matches)
    except FileNotFoundError:
        print(f'Error: File not found at : {file_path}')
    except Exception as e:
        print(f'An error occurred: {e}')

