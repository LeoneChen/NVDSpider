# NVDSpider

## Introduce

Crawl CVE Info related to customized key word (set in class member `nvd_search_key_word` in `NVDSpider/spiders/NVD.py`). 

Output format could be found in `NVDSpider/settings.py`.

## Prerequisites
It's based on Scrapy( https://github.com/scrapy/scrapy ). So we need download scrapy.
```python
pip install scrapy
```

Because of the need of crawling papers related to CVE in Google Scholar, so I add proxy in `NVDSpider/middlewares.py`, so adjust the proxy before executing.

## Notice

I have tried a lot of settings in order to resist anti-crawler mechanism, the details are in `settings.py` and `middlewares.py`

## How to run

```python
python main.py
```

