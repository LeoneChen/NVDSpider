from scrapy.crawler import CrawlerProcess
from NVDSpider.spiders.NVD import NvdSpider
from scrapy.utils.project import get_project_settings

if __name__ == '__main__':
    process = CrawlerProcess(get_project_settings())
    process.crawl(NvdSpider)
    process.start()
