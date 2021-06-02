from scrapy.crawler import CrawlerProcess
from NVDSpider.spiders.NVD import NvdSpider
from scrapy.utils.project import get_project_settings
import os

if __name__ == '__main__':
    if os.path.exists("output.csv"):
        os.remove("output.csv")
    process = CrawlerProcess(get_project_settings())
    process.crawl(NvdSpider)
    process.start()
