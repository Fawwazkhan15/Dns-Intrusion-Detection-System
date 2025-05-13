import random
import string
import time
import dns.resolver

def random_subdomain(length=10):
    """Generate a random subdomain."""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def generate_dns_traffic(domain, queries_per_second=10):
    """Generate DNS traffic by sending queries for random subdomains."""
    resolver = dns.resolver.Resolver()
    while True:
        try:
            subdomain = f"{random_subdomain()}.{domain}"
            print(f"Querying: {subdomain}")
            resolver.resolve(subdomain, "A")
        except dns.resolver.NXDOMAIN:
            print(f"NXDOMAIN: {subdomain} does not exist.")
        except Exception as e:
            print(f"Error querying {subdomain}: {e}")

        time.sleep(1 / queries_per_second)

if __name__ == "__main__":
    target_domain = "malicious.com"  # Replace with your target domain
    queries_per_sec = 20  # Adjust the number of queries per second

    print(f"Generating DNS traffic for domain: {target_domain} with {queries_per_sec} QPS")
    generate_dns_traffic(target_domain, queries_per_sec)
