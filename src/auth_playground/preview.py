"""Preview of the HTTP requests the playground sends."""

from dataclasses import dataclass
from dataclasses import field

# Shown in place of the values generated when the request is sent.
GENERATED = "[generated]"

# Shown in place of the secrets.
HIDDEN = "[hidden]"


@dataclass
class RequestPreview:
    """An HTTP request, as shown to the user.

    The parameters go in the query string of a GET request, and in the
    form-encoded body of a POST request.
    """

    method: str
    url: str
    params: list[tuple[str, str]]
    headers: list[tuple[str, str]] = field(default_factory=list)

    def lines(self):
        """Return the request as text lines, one per parameter."""
        lines = [f"{self.method} {self.url}"]
        if self.method == "GET":
            lines += [
                f"  {'&' if index else '?'}{name}={value}"
                for index, (name, value) in enumerate(self.params)
            ]
            return lines

        lines += [f"{name}: {value}" for name, value in self.headers]
        lines.append("")
        lines += [
            f"{'&' if index else ''}{name}={value}"
            for index, (name, value) in enumerate(self.params)
        ]
        return lines
