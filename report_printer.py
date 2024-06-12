def print_vulnerabilities(file_path):
    with open(file_path, 'r') as file:
        vulnerabilities = file.read()
        print(vulnerabilities)
        return vulnerabilities
