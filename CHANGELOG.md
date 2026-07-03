# Changelog

All notable changes to VoidAccess are documented here.

## [1.6.0] - 2026-07-02
### Added
- Optional clearnet ScrapingAnt integration for paste sites and RSS feeds.
- Three independent ScrapingAnt products are now documented and supported separately: Web Scraping API, Residential Proxy transport, and Datacenter Proxy transport.
- Web Scraping API transport uses `VOIDACCESS_USE_PROXIES=true` and `SCRAPINGANT_API_KEY`.
- Residential Proxy transport uses `VOIDACCESS_USE_PROXY=true` with `SCRAPINGANT_PROXY_USERNAME` and `SCRAPINGANT_PROXY_PASSWORD`.
- Datacenter Proxy transport is configured with `SCRAPINGANT_PROXY_TYPE=datacenter` and the same proxy credentials, but live verification is still open.
- The transport selection model is mutually exclusive per request; if both transports are enabled, the proxy transport wins for that request and the chokepoint logs the choice once.
- Tor, `.onion`, GitHub, and GitLab traffic remain unaffected by the integration.

### Fixed
- Corrected earlier documentation and configuration drift that conflated the Web Scraping API credential with the proxy credentials and described the wrong host model.
- Clarified that there is no chained transport mode.
