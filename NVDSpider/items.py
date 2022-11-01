# Define here the models for your scraped items
#
# See documentation in:
# https://docs.scrapy.org/en/latest/topics/items.html

import scrapy


class NvdspiderItem(scrapy.Item):
    # define the fields for your item here like:
    # name = scrapy.Field()
    cve_id = scrapy.Field()
    current_description = scrapy.Field()
    cvss3_score = scrapy.Field()
    cvss2_score = scrapy.Field()
    cwe = scrapy.Field()
    reference = scrapy.Field()
    paper = scrapy.Field()
