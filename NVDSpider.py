import scrapy, re, functools
from scrapy.crawler import CrawlerProcess
from items import NVDItem


def patch_first(left, right):
    left_is_patch = bool(re.search("patch", left["type"], re.IGNORECASE))
    right_is_patch = bool(re.search("patch", right["type"], re.IGNORECASE))
    if left_is_patch and not right_is_patch:
        return 1
    elif left_is_patch and right_is_patch:
        return 0
    else:
        return -1


class NVDSpider(scrapy.Spider):
    name = 'NVDSpider'

    cve_detail_url_prefix = "https://nvd.nist.gov/vuln/detail/"

    def start_requests(self):
        start_url = 'https://nvd.nist.gov/vuln/search/results' \
                    '?form_type=Basic&results_type=overview' \
                    '&query=' + nvd_search_key_word + '&search_type=all&startIndex=0'
        yield scrapy.Request(start_url, callback=self.parse, dont_filter=True)

    def parse(self, response):
        cve_count = int(response.xpath("//strong[@data-testid='vuln-matching-records-count']/text()").get().strip())
        for start_index in range(0, cve_count, 20):
            result_url = "https://nvd.nist.gov/vuln/search/results" \
                         "?form_type=Basic&results_type=overview&search_type=all" \
                         "&query=" + nvd_search_key_word + "&startIndex=" + str(start_index)
            yield scrapy.Request(result_url, callback=self.parse_result_page)

    def parse_result_page(self, response):
        cve_lists = response.xpath("//table[@data-testid='vuln-results-table']/tbody/tr/th/strong/a/text()").getall()
        for cve in cve_lists:
            yield scrapy.Request(self.cve_detail_url_prefix + cve.strip(), callback=self.parse_cve_detail)

    def parse_cve_detail(self, response):
        cve_detail = NVDItem()
        cve_detail['cve_id'] = response.xpath("//span[@data-testid='page-header-vuln-id']/text()").get().strip()
        cve_detail['current_description'] = response.xpath("//p[@data-testid='vuln-description']/text()").get().strip()
        cve_detail['cvss3_score'] = response.xpath(
            "//span[has-class('severityDetail')]")[0].xpath("a/text()").get().strip()
        cve_detail['cvss2_score'] = response.xpath(
            "//span[has-class('severityDetail')]")[1].xpath("a/text()").get().strip()
        cvss3_vector = response.xpath(
            "//span[contains(@data-testid,'vuln-cvss3-nist-vector')]/text()").get().strip()
        cve_detail['cvss3_vector'] = " ".join(re.sub("[\t\n\r]", ' ', cvss3_vector).split())
        cve_detail['cvss2_vector'] = response.xpath(
            "//span[contains(@data-testid,'vuln-cvss2-panel-vector')]/text()").get().strip()
        cwes = []
        cwe = {}
        for cwe_row in response.xpath("//tr[contains(@data-testid,'vuln-CWEs-row-')]"):
            cwe.update({"id": cwe_row.xpath("td[contains(@data-testid,'vuln-CWEs-link-')]/a/text()").get()})
            cwe.update({"txt": cwe_row.xpath("td[contains(@data-testid,'vuln-CWEs-link-')]")[1].xpath("text()").get()})
            cwes.append(cwe)
        cve_detail['cwe'] = cwes

        references = []
        reference = {}
        for reference_row in response.xpath("//tr[contains(@data-testid,'vuln-hyperlinks-row-')]"):
            reference.update(
                {"link": reference_row.xpath("td[contains(@data-testid,'vuln-hyperlinks-link-')]/a/text()").get()})
            reference.update({"type": ",".join(reference_row.xpath(
                "td[contains(@data-testid,'vuln-hyperlinks-resType-')]//span[has-class('badge')]/text()").getall())})
            references.append(reference)
            references.sort(key=functools.cmp_to_key(patch_first))
        cve_detail['reference'] = references

        yield cve_detail


if __name__ == '__main__':
    nvd_search_key_word = "sgx"
    process = CrawlerProcess(settings={"FEED_FORMAT": 'jl', "FEED_URI": 'nvd.jl'})
    process.crawl(NVDSpider)
    process.start()
