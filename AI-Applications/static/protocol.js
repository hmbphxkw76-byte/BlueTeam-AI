(function () {
  function targetUrl(protocol) {
    const url = new URL(window.location.href);
    url.protocol = protocol;

    if (protocol === "https:") {
      url.port = url.port === "8000" || url.port === "" ? "8443" : url.port;
    } else {
      url.port = url.port === "8443" || url.port === "" ? "8000" : url.port;
    }

    return url.toString();
  }

  function createLink(label, protocol) {
    const link = document.createElement("a");
    link.href = targetUrl(protocol);
    link.textContent = label;
    if (window.location.protocol === protocol) {
      link.className = "active";
      link.setAttribute("aria-current", "page");
    }
    return link;
  }

  function mount() {
    if (document.querySelector(".protocol-switch")) {
      return;
    }
    const switcher = document.createElement("nav");
    switcher.className = "protocol-switch";
    switcher.setAttribute("aria-label", "HTTP HTTPS 切换");
    switcher.append(createLink("HTTP", "http:"), createLink("HTTPS", "https:"));
    document.body.append(switcher);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", mount);
  } else {
    mount();
  }
})();
