import argparse

def generate_ips(base_ip, start=1, end=254):
    """
    Generate a list of IP addresses based on the base IP and range.

    Parameters:
    - base_ip (str): The base IP to use, e.g., "84.100.22.210"
    - start (int): The starting value for the last octet.
    - end (int): The ending value for the last octet.

    Returns:
    - list: A list of generated IP addresses.
    """
    ip_parts = base_ip.split('.')
    if len(ip_parts) != 4:
        raise ValueError("Invalid base IP format. Use xxx.xxx.xxx.xxx format.")

    generated_ips = []
    for i in range(start, end + 1):
        new_ip = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.{i}"
        generated_ips.append(new_ip)

    return generated_ips


def main():
    parser = argparse.ArgumentParser(description="Generate a list of sequential IP addresses based on the base IP.")
    parser.add_argument("base_ip", help="The base IP to use, e.g., '84.100.22.210'")
    parser.add_argument("--start", type=int, default=1, help="Starting value within last octet (e.g. 1)")
    parser.add_argument("--end", type=int, default=254, help="End value within last octet (e.g. 100)")

    args = parser.parse_args()

    try:
        ip_addresses = generate_ips(args.base_ip, args.start, args.end)
        for ip in ip_addresses:
            print(ip)
    except ValueError as e:
        print(e)


if __name__ == "__main__":
    main()
