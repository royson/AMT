# Crawl URL from nvd references and extract information.
# Royson Lee - 15 March 2017

import scrapy
from twisted.internet import reactor
from scrapy.crawler import CrawlerRunner
import xml.etree.ElementTree as ET
from scrapy.utils.log import configure_logging
import psycopg2 as pg
from psycopg2.extensions import AsIs
import re

fname = 'allcvesfrommitre.xml'

connect_str = "dbname='cve' user='postgres' host='127.0.0.1' password='Pa$$w0rd'"

conn = pg.connect(connect_str)
cursor = conn.cursor()


class MySpider(scrapy.Spider):
    name = "spid"

    def start_requests(self):
        print("******************STARTING**********************")

        cve = ""
        
        for data in self.data:
            #ends with a digit
            m = re.search(r'\d+$', data)
            
            if data.startswith("CVE:"):
                cve = data[4:]
            #SecurityFocus
            elif data.startswith('http://www.securityfocus.com/bid/') and m is not None:
                req = scrapy.Request(url=data, callback=self.parseSecurityFocusInfo)
                req.meta['cve'] = cve
                req.meta['url'] = data.strip('\n')
                yield req

            #SecurityTracker
            elif data.startswith('http://www.securitytracker.com/id?') and m is not None:
                req = scrapy.Request(url=data, callback=self.parseSecurityTracker)
                req.meta['cve'] = cve
                req.meta['url'] = data.strip('\n')
                yield req

            #[*] Extend your website here

    #http://www.securitytracker.com/id?

    def parseSecurityTracker(self,response):
        url = response.meta['url']
        cve = response.meta['cve'] 

        desc_line = 48
        imp_line = 49
        sol_line = 50

        desc_offset = 63
        imp_offset = 58
        sol_offset = 60

        vul_desc = response.xpath('.//tr')[desc_line]

        if vul_desc.xpath('.//td//b//text()').extract_first().startswith('Version'):
            desc_line = desc_line + 1
            imp_line = imp_line + 1
            sol_line = sol_line + 1
        
        vul_desc = response.xpath('.//tr')[desc_line]
        desc = vul_desc.xpath('.//td//font').extract_first()[desc_offset:].split("</font>",1)[0]
            
        vul_imp = response.xpath('.//tr')[imp_line]
        imp = vul_imp.xpath('.//td//font').extract_first()[imp_offset:].split('</font>',1)[0]

        vul_sol = response.xpath('.//tr')[sol_line]
        sol = vul_sol.xpath('.//td//font').extract_first()[sol_offset:].split('</font>',1)[0]

        cursor.execute("SELECT count(1) FROM securitytracker WHERE url = %s", (url,))

        exist = cursor.fetchone()

        if exist[0] == 0:
            print("************ INSERTING " + cve + " INTO DATABASE **************")
            cursor.execute('INSERT INTO securitytracker (cve, url, description, impact, \
                solution) VALUES (%s, %s, %s, %s, %s)', (cve, url, desc, imp, sol))
            conn.commit()
        else:
            print("************ URL " + url + " EXISTED **************")
            
                
    #http://www.securityfocus.com/bid/

    def parseSecurityFocusInfo(self, response):
        # Obsolete code. CVE might not be always there.
        # cve_field = response.xpath('.//div[@id="vulnerability"]//td')[5]
        # cve = cve_field.xpath('normalize-space(.//text())').extract_first()


        class_elem = response.xpath('.//div[@id="vulnerability"]//td')[3]
        class_field = class_elem.xpath('normalize-space(.//text())').extract_first()

        url = response.meta['url']
        cve = response.meta['cve']

        urls = [url+'/discuss',
                    url+'/exploit',
                    url+'/solution']

        #check if record exists
        cursor.execute("SELECT count(1) FROM securityfocus WHERE url = %s", (url,))

        exist = cursor.fetchone()

        if exist == 0:
            print("************ INSERTING " + cve + " INTO DATABASE **************")
            cursor.execute('INSERT INTO securityfocus (cve, url) VALUES (%s, %s)', (cve,url))
            conn.commit()

        print("************ UPDATE CLASS " + class_field + " for CVE "+cve+" **************")
        cursor.execute('UPDATE securityfocus SET class = %s WHERE cve = %s', (class_field, cve))

        for s_url in urls:
            req = scrapy.Request(url=s_url, callback=self.parseSecurityFocus)
            req.meta['cve'] = cve
            yield req
        
    def parseSecurityFocus(self, response):
        cve = response.meta['cve']
        ins = ""
        for text in response.xpath('//div[@id="vulnerability"]/text()').extract():
            ins = ins + text

        #insert DB
        page = response.url.split("/")[-1]
        
        cursor.execute('UPDATE securityfocus SET %s = %s WHERE cve = %s', (AsIs(page), ins, cve))
        conn.commit()


#input_data will consist of a CVE identifier followed by a list of urls reference it
input_data = []
r = ET.parse(fname).getroot()

for v in r.iter('{http://www.icasi.org/CVRF/schema/vuln/1.1}Vulnerability'):
    for child in v:
        # print(child.tag)
        if child.tag == '{http://www.icasi.org/CVRF/schema/vuln/1.1}Title':
            input_data.append('CVE:' +  child.text)

        # if child.tag == '{http://www.icasi.org/CVRF/schema/vuln/1.1}Notes':
        if child.tag == '{http://www.icasi.org/CVRF/schema/vuln/1.1}References':
              for ref in child:
                    for url in ref:
                        if url.tag == '{http://www.icasi.org/CVRF/schema/vuln/1.1}URL' and url.text != None:
                          if url.text.startswith('http://'):
                            input_data.append(url.text)

#Start Crawler
configure_logging({'LOG_FORMAT': '%(levelname)s: %(message)s'})
runner = CrawlerRunner()

d = runner.crawl(MySpider, data = input_data)
d.addBoth(lambda _: reactor.stop())

reactor.run()

cursor.close()
conn.close()
