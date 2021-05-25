#NVDSpider

Crawl CVE Info related to customized key word (set in class member `nvd_search_key_word` in `NVDSpider/spiders/NVD.py`). 

Output format could be found in `NVDSpider/settings.py`.

It's based on Scrapy( https://github.com/scrapy/scrapy ). So firstly download scrapy.
```python
pip install scrapy
```