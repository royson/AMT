# Extract information from cvedetails.com 
# Royson Lee - 17 March 2017

import scrapy
from twisted.internet import reactor
from scrapy.crawler import CrawlerRunner
from scrapy.utils.log import configure_logging
import psycopg2 as pg
from psycopg2.extensions import AsIs

connect_str = "dbname='cve' user='postgres' host='127.0.0.1' password='Pa$$w0rd'"

conn = pg.connect(connect_str)
cursor = conn.cursor()


class MySpider(scrapy.Spider):
    name = "spid"

    def start_requests(self):
        print("******************STARTING**********************")

        for data in self.data:
            yield scrapy.Request(url=data, callback=self.parseInfo)

    def parseInfo(self, response):
        point = 3
        result = response.xpath('//tr[@class="srrowns"]//td//text()').extract()

        while point < len(result):
            cve = result[point]
            cwe = ' '.join(result[point+1].split())
            if cwe != '':
                point = point+1
            noOfExploits = ' '.join(result[point+2].split())
            vulnType = ' '.join(result[point+4].split())
            score = ' '.join(result[point+7].split())
            gainedAccessLvl = ' '.join(result[point+8].split())
            access = ' '.join(result[point+9].split())
            complexity = ' '.join(result[point+10].split())
            auth = ' '.join(result[point+11].split())
            conf = ' '.join(result[point+12].split())
            inte = ' '.join(result[point+13].split())
            ava = ' '.join(result[point+14].split())
            point = point + 18

            #check if record exists
            cursor.execute("SELECT count(1) FROM cvedetail WHERE cve = %s", (cve,))

            exist = cursor.fetchone()

            if exist[0] == 0:
                print("************ INSERTING " + cve + " INTO DATABASE **************")
                cursor.execute('INSERT INTO cvedetail (cve, cwe, no_of_exploits, vuln_type, cvss, gained_access_level, \
                    access, complexity, authentication, confidentiality, integrity, availability) \
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)', 
                    (cve, cwe, noOfExploits, vulnType, score, gainedAccessLvl, access, complexity,
                    auth, conf, inte, ava))
                conn.commit()


url = "http://www.cvedetails.com/vulnerability-list.php?vendor_id=0&product_id=0&version_id=0&page="
backUrl = "&hasexp=0&opdos=0&opec=0&opov=0&opcsrf=0&opgpriv=0&opsqli=0&opxss=0&opdirt=0&opmemc=0&\
ophttprs=0&opbyp=0&opfileinc=0&opginf=0&cvssscoremin=0&cvssscoremax=0&year=0&month=0&cweid=0&order=1&\
trc=85121&sha=3cf9994d68386594f1283fc226cf51dad5fe72b8"
noOfPages = 1703
input_data = [ url + str(x) + backUrl for x in range(1,noOfPages+1) ]

#Start Crawler
configure_logging({'LOG_FORMAT': '%(levelname)s: %(message)s'})
runner = CrawlerRunner()

d = runner.crawl(MySpider, data = input_data)
d.addBoth(lambda _: reactor.stop())

reactor.run()

cursor.close()
conn.close()
