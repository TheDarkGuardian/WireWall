"""Generate a provisionable, editable Grafana dashboard from metric contracts."""
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
DS={'type':'prometheus','uid':'wirewall-prometheus'}

def main():
    panels=[]
    def panel(title,expression,x,y,w=12,h=9,kind='timeseries',unit='short',legend=None,description=''):
        expressions=expression if isinstance(expression,list) else [(expression,legend or title)]
        p={'id':len(panels)+1,'title':title,'description':description,'type':kind,'datasource':DS,'gridPos':{'x':x,'y':y,'w':w,'h':h},
           'targets':[{'refId':chr(65+i),'expr':expr,'legendFormat':label,'datasource':DS,'instant':kind in ['stat','bargauge'],'range':kind=='timeseries','format':'time_series','editorMode':'code'} for i,(expr,label) in enumerate(expressions)],
           'fieldConfig':{'defaults':{'unit':unit,'color':{'mode':'palette-classic'},'thresholds':{'mode':'absolute','steps':[{'color':'green','value':None}]},'mappings':[]},'overrides':[]}}
        if kind=='timeseries':p['options']={'legend':{'displayMode':'list','placement':'bottom','showLegend':True},'tooltip':{'mode':'multi','sort':'desc'}};p['fieldConfig']['defaults']['custom']={'drawStyle':'line','lineWidth':1.5,'fillOpacity':8,'showPoints':'never','spanNulls':False}
        elif kind=='stat':p['options']={'reduceOptions':{'calcs':['lastNotNull'],'fields':'','values':False},'orientation':'auto','textMode':'value','colorMode':'value','graphMode':'none'}
        else:p['options']={'reduceOptions':{'calcs':['lastNotNull'],'fields':'','values':False},'orientation':'horizontal','displayMode':'gradient','showUnfilled':True}
        panels.append(p);return p
    p=panel('Firewall gözlemi','min(up{job="wirewall"}) * (min(wirewall_up) or vector(0))',0,0,4,5,'stat',description='Exporter erişimi ve10s içindeki sağlıklı veri yolu gözlemi birlikte değerlendirilir.')
    p['fieldConfig']['defaults']['mappings']=[{'type':'value','options':{'0':{'text':'SAĞLIKLI DEĞİL','color':'red'},'1':{'text':'SAĞLIKLI','color':'green'}}}]
    p=panel('Çalışma modu','wirewall_info',4,0,4,5,'stat',legend='{{xdp_mode}} / {{firewall_mode}}');p['options']['textMode']='name'
    panel('Politika sürümü','wirewall_policy_version',8,0,4,5,'stat')
    panel('Etkin IP engeli','wirewall_active_bans',12,0,4,5,'stat')
    p=panel('Aktivasyon onayı bekliyor','wirewall_activation_pending',16,0,4,5,'stat');p['fieldConfig']['defaults']['thresholds']['steps'].append({'color':'orange','value':1})
    p=panel('Sentetik veri işareti','wirewall_simulated',20,0,4,5,'stat');p['fieldConfig']['defaults']['mappings']=[{'type':'value','options':{'0':{'text':'GERÇEK LINUX','color':'green'},'1':{'text':'LABORATUVAR','color':'orange'}}}]
    panel('XDP paket hızı', [('rate(wirewall_received_packets_total[1m])','Gelen'),('rate(wirewall_dropped_packets_total[1m])','DROP'),('rate(wirewall_would_drop_packets_total[1m])','Gözlem önerisi')],0,5,unit='pps',description='Örneklenmeyen paket sayaçlarının hızı; bağlantı veya saldırı sayısı değildir.')
    panel('Gelen trafik hızı','rate(wirewall_received_bytes_total[1m])*8',12,5,unit='bps',description='IP/frame byte muhasebesi; fiziksel hat overhead ölçümü değildir.')
    panel('Stateful host kararları','sum by(verdict) (rate(wirewall_nft_packets_total[1m]))',0,14,legend='{{verdict}}',unit='pps',description='Yalnız WireWall host-input tablosu, XDP sonrası. Tablo değişiminde sayaç sıfırlanır.')
    panel('Protokol dağılımı','rate(wirewall_protocol_packets_total[1m])',12,14,legend='{{protocol}}',unit='pps')
    panel('XDP ret nedenleri','rate(wirewall_reason_packets_total[1m])',0,23,legend='{{reason}}',unit='pps',description='Gözlem modunda ret önerileri de dahildir.')
    panel('Paylaşılan VDS kaynakları',[('wirewall_host_cpu_ratio','CPU'),('wirewall_host_memory_used_bytes / wirewall_host_memory_total_bytes','RAM')],12,23,unit='percentunit',description='Host geneli ölçümüdür; yalnız firewall CPU/RAM kullanımı değildir. CPU steal dahildir.')
    panel('İzlenen ilk10 hedef port','topk(10,rate(wirewall_service_packets_total[1m]))',0,32,kind='bargauge',legend='{{protocol}} / {{port}}',unit='pps',description='En fazla1024 port/protokol izlenir; yalnız güncel top20 seri dışa verilir. Port, çalışan uygulama kanıtı değildir.')
    panel('Host conntrack doluluğu','wirewall_host_conntrack_entries / wirewall_host_conntrack_capacity',12,32,6,9,'stat','percentunit',description='Host gerçek conntrack sayısı/kapasitesi; panelin256satırlık listesi değildir.')
    p=panel('Kaybolan olay kaydı','wirewall_event_drops_total',18,32,6,9,'stat',description='Olay kaybı paket düşürme sayısı değildir.');p['fieldConfig']['defaults']['thresholds']['steps'].append({'color':'orange','value':1})
    p=panel('Servis sınıflandırma taşması','wirewall_service_stats_overflow_packets_total',0,41,8,5,'stat',description='1024 anahtar dolduktan sonra port dağılımında sayılmayan paketler. Filtre kararı etkilenmez.');p['fieldConfig']['defaults']['thresholds']['steps'].append({'color':'orange','value':1})
    p=panel('Kaynak bütçesi kapasite fallback','wirewall_map_capacity_failures_total',8,41,8,5,'stat',description='Kaynak tablosu dolduğunda toplam bütçe korunur.');p['fieldConfig']['defaults']['thresholds']['steps'].append({'color':'orange','value':1})
    p=panel('nftables sayaç okuması','wirewall_nft_available',16,41,8,5,'stat');p['fieldConfig']['defaults']['mappings']=[{'type':'value','options':{'0':{'text':'OKUNAMIYOR','color':'red'},'1':{'text':'OKUNUYOR','color':'green'}}}]
    panels.append({'id':len(panels)+1,'title':'Ölçüm kapsamı','type':'text','gridPos':{'x':0,'y':46,'w':24,'h':4},'options':{'mode':'markdown','content':'XDP sayaçları program yeniden yüklenince, nftables sayaçları tablo değişince sıfırlanır. `rate()` sıfırlamayı hesaba katar. Veriler kurulumdan itibaren birikir; geçmiş veri üretilmez. Paket olayı örnekleri ve filtrelenmiş raporlar WireWall **Olay Geçmişi** sayfasındadır. Bu panel bağlantı/saldırı sayımı veya upstream DDoS kapasitesi göstermez.'}})
    dashboard={'uid':'wirewall-l4','title':'WireWall','tags':['wirewall','layer4','xdp'],'timezone':'browser','schemaVersion':39,'version':1,'editable':True,'refresh':'5s','time':{'from':'now-15m','to':'now'},'panels':panels,'annotations':{'list':[]}}
    destination=ROOT/'deploy/monitoring/wirewall-dashboard.json';destination.write_text(json.dumps(dashboard,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'panels':len(panels),'path':str(destination)}))

if __name__=='__main__':main()
