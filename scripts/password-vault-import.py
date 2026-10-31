#!/usr/bin/env python3
"""Import JSON credentials from stdin without writing their values to disk."""
import argparse
import ipaddress
import json
import pathlib
import sys
import urllib.error
import urllib.parse
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def safe_url(value):
    url = urllib.parse.urlsplit(value)
    if url.username or url.password or url.query or url.fragment or url.path not in ('', '/'):
        return False
    if url.scheme == 'https' and url.hostname:
        return True
    if url.scheme != 'http' or not url.hostname:
        return False
    try:
        return ipaddress.ip_address(url.hostname).is_loopback
    except ValueError:
        return False


def valid(rows):
    if not isinstance(rows, list) or len(rows) > 1000:
        return False
    seen = set()
    for row in rows:
        required = {'request_id', 'kind', 'title', 'site', 'username', 'password', 'shared'}
        if not isinstance(row, dict) or not required.issubset(row) or set(row) - required - {'owner_id'}:
            return False
        request = row['request_id']
        if (not isinstance(request, str) or len(request) != 32 or
                any(c not in '0123456789abcdef' for c in request) or request in seen or
                row['kind'] not in ('website', 'game', 'service') or
                type(row['shared']) is not bool or ('owner_id' in row and (not isinstance(row['owner_id'], str) or not row['owner_id'])) or
                not all(isinstance(row[k], str) for k in ('title', 'site', 'username', 'password')) or
                not row['title'].strip() or not row['password'] or
                len(row['title'].encode('utf8')) > 256 or len(row['site'].encode('utf8')) > 2048 or
                len(row['username'].encode('utf8')) > 512 or len(row['password'].encode('utf8')) > 4096):
            return False
        seen.add(request)
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', help='HTTPS origin, or local loopback HTTP origin')
    parser.add_argument('--token-file', help='Private file containing a platform token')
    parser.add_argument('--organization', required=True, help='Target organization ID')
    parser.add_argument('--dry-run', action='store_true', help='Validate input without network access')
    args = parser.parse_args()
    if not args.organization or len(args.organization) > 64:
        raise ValueError('Invalid organization')
    rows = json.load(sys.stdin)
    if not valid(rows):
        raise ValueError('Invalid import input')
    if args.dry_run:
        print('Validated %d records; no data was sent.' % len(rows))
        return
    if not args.url or not args.token_file or not safe_url(args.url):
        raise ValueError('A verified HTTPS origin or loopback HTTP origin and token are required')
    token = pathlib.Path(args.token_file).read_text(encoding='utf8').strip()
    if not token or '\n' in token or '\r' in token:
        raise ValueError('Invalid platform token')
    url = args.url.rstrip('/') + '/api/v1/password-vault/items'
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    for index, row in enumerate(rows):
        request = urllib.request.Request(url, data=json.dumps(row).encode('utf8'), method='POST', headers={
            'Authorization': 'Bearer ' + token,
            'Content-Type': 'application/json',
            'X-JMS-ORG': args.organization,
        })
        try:
            with opener.open(request, timeout=30) as response:
                if response.status != 201:
                    raise ValueError('Unexpected response')
        except (urllib.error.URLError, ValueError) as error:
            print('Import stopped after %d of %d records; retry the same input.' % (index, len(rows)), file=sys.stderr)
            raise RuntimeError('Vault import failed') from error
    print('Imported or confirmed %d records.' % len(rows))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # Exception text may contain an HTTP response or other private data.
        print('Vault import did not complete.', file=sys.stderr)
        sys.exit(1)
