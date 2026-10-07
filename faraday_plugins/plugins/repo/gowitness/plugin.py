"""
Faraday Penetration Test IDE
Copyright (C) 2026  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""
import json
from urllib.parse import urlsplit

from dateutil.parser import parse

from faraday_plugins.plugins.plugin import PluginMultiLineJsonFormat


class GowitnessPlugin(PluginMultiLineJsonFormat):
    """Parse Gowitness 3.x reports produced by --write-jsonl."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.id = "gowitness"
        self.name = "Gowitness"
        self.plugin_version = "1.0.0"
        self.version = "3.1.1"
        self.extension = [".json", ".jsonl"]
        self.json_keys = {
            "url",
            "final_url",
            "response_code",
            "perception_hash",
            "file_name",
        }

    @staticmethod
    def _parse_run_date(value):
        if not value:
            return None
        try:
            return parse(value)
        except (TypeError, ValueError, OverflowError):
            return None

    @staticmethod
    def _url_without_credentials(value):
        if not isinstance(value, str):
            return value
        value = value.strip()
        try:
            parsed_url = urlsplit(value)
            hostname = parsed_url.hostname
            port = parsed_url.port
        except ValueError:
            return ""
        if not hostname or (
            parsed_url.username is None and parsed_url.password is None
        ):
            return value

        authority = f"[{hostname}]" if ":" in hostname else hostname
        if port is not None:
            authority += f":{port}"
        return parsed_url._replace(netloc=authority).geturl()

    @staticmethod
    def _build_response(result):
        response = []
        response_code = result.get("response_code")
        if response_code:
            status = " ".join(filter(None, [
                str(result.get("protocol") or "HTTP"),
                str(response_code),
                str(result.get("response_reason") or ""),
            ]))
            response.append(status)
        if result.get("content_length") is not None:
            response.append(f"Content-Length: {result['content_length']}")
        return "\n".join(response)

    @staticmethod
    def _build_technical_data(result, source_url, target_url):
        data = []
        if source_url and source_url != target_url:
            data.append(f"Source URL: {source_url}")
            data.append(f"Final URL: {target_url}")
        else:
            data.append(f"URL: {target_url}")

        fields = (
            ("Title", "title"),
            ("Protocol", "protocol"),
            ("Response code", "response_code"),
            ("Response reason", "response_reason"),
            ("Content length", "content_length"),
            ("Screenshot file", "file_name"),
            ("Perception hash", "perception_hash"),
        )
        for label, key in fields:
            value = result.get(key)
            if value not in (None, ""):
                data.append(f"{label}: {value}")

        technologies = result.get("technologies") or []
        if not isinstance(technologies, list):
            technologies = []
        technologies = sorted({
            str(technology.get("value")).strip()
            for technology in technologies
            if isinstance(technology, dict) and technology.get("value")
        })
        if technologies:
            data.append(f"Technologies: {', '.join(technologies)}")

        tls = result.get("tls") or {}
        tls_keys = (
            "protocol",
            "key_exchange",
            "cipher",
            "subject_name",
            "issuer",
            "san_list",
            "server_signature_algorithm",
            "encrypted_client_hello",
        )
        if isinstance(tls, dict) and any(tls.get(key) for key in tls_keys):
            tls_fields = (
                ("TLS protocol", "protocol"),
                ("TLS key exchange", "key_exchange"),
                ("TLS cipher", "cipher"),
                ("TLS subject", "subject_name"),
                ("TLS issuer", "issuer"),
                ("TLS valid from", "valid_from"),
                ("TLS valid to", "valid_to"),
                ("TLS server signature algorithm", "server_signature_algorithm"),
            )
            for label, key in tls_fields:
                value = tls.get(key)
                if value not in (None, "", 0):
                    data.append(f"{label}: {value}")

            san_list = tls.get("san_list") or []
            if not isinstance(san_list, list):
                san_list = []
            san_values = sorted({
                str(san.get("value")).strip()
                for san in san_list
                if isinstance(san, dict) and san.get("value")
            })
            if san_values:
                data.append(f"TLS SANs: {', '.join(san_values)}")
            if tls.get("encrypted_client_hello"):
                data.append("TLS encrypted client hello: true")

        return "\n".join(data)

    def parseOutputString(self, output, debug=False):
        for line_number, line in enumerate(output.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                result = json.loads(line)
            except (json.JSONDecodeError, TypeError) as error:
                self.logger.warning(
                    "Skipping invalid Gowitness record on line %s: %s",
                    line_number,
                    error,
                )
                continue

            if not isinstance(result, dict):
                self.logger.warning(
                    "Skipping non-object Gowitness record on line %s",
                    line_number,
                )
                continue
            if result.get("failed"):
                continue

            source_url = self._url_without_credentials(result.get("url"))
            final_url = self._url_without_credentials(result.get("final_url"))
            target_url = final_url or source_url
            if not isinstance(target_url, str):
                continue
            target_url = target_url.strip()

            try:
                parsed_url = urlsplit(target_url)
                scheme = parsed_url.scheme.lower()
                hostname = parsed_url.hostname
                port = parsed_url.port
            except ValueError:
                continue
            if scheme not in ("http", "https") or not hostname:
                continue
            if port is None:
                port = 443 if scheme == "https" else 80
            if port < 1:
                continue

            host_id = self.createAndAddHost(
                name=self.resolve_hostname(hostname),
                hostnames=[hostname],
            )

            negotiated_protocol = result.get("protocol") or ""
            service_description = "Gowitness web service"
            if negotiated_protocol:
                service_description += f" using {negotiated_protocol}"
            service_id = self.createAndAddServiceToHost(
                host_id=host_id,
                name=scheme,
                protocol="tcp",
                ports=port,
                status="open",
                version=negotiated_protocol,
                description=service_description,
            )

            title = result.get("title") or ""
            description = f"Gowitness captured {target_url}"
            if title:
                description += f' with title "{title}"'
            if source_url and source_url != target_url:
                description += f" after redirecting from {source_url}"

            self.createAndAddVulnWebToService(
                host_id=host_id,
                service_id=service_id,
                name=f"Gowitness capture: {target_url}",
                desc=description,
                severity="info",
                website=f"{scheme}://{parsed_url.netloc}",
                path=parsed_url.path or "/",
                query=parsed_url.query,
                method="GET",
                response=self._build_response(result),
                status_code=result.get("response_code"),
                run_date=self._parse_run_date(result.get("probed_at")),
                data=self._build_technical_data(result, source_url, target_url),
            )


def createPlugin(*args, **kwargs):
    return GowitnessPlugin(*args, **kwargs)
