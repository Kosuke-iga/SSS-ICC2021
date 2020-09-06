//package javatips;
import java.lang.Runtime;
import java.lang.Process;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.IOException;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.util.Timer;
import java.util.TimerTask;
import java.io.IOException;
import java.util.Scanner;
import java.util.Arrays;
import java.util.Date;
import java.io.LineNumberReader;
import java.util.Collections;
import java.util.*;

public class ELTHunter{
  public static void main(String[] args){
    int duration=11;
    boolean attack=true; //攻撃者端末で実験時. In attack scenario, tarMAC5 is regarded as the AP on the other side
    //do{
//各設定値
      int repeat=20; //実験用にx回リピート設定
      long[] timer=new long[repeat]; //各回の検知時間

      int detectcnt=0; //repeat中何回検知できたか
      int failed=0; //悪性を検知できなかった

      int giveups=0; //要求待ち断念
      int attacked=0; //攻撃されてしまった
      int safe=0; //安全LAN
      double nicejudge; //正解ジャッジrate
      double badjudge; //不正解ジャッジrate
      int oops=0; //repeat中何回正規APを誤って悪性APと検知してしまったか
      int aps=0; //total APs investigated
      String gw="10.4.64.1"; //default gateway.コマンドから入手できるようにする．
      boolean forzikkenn=true; //実験用の時チャネル変化を考えない（初めから攻撃者混入と考える）
      boolean imac=false; //iMacならtrue
      int repeatcnt=repeat;
      int otosCnt=0;
      String lap="74:da:88:8a:07:e5"; //LAPと同じBSSIDに設定しないように
      String lap5="74:da:88:8a:07:e4";
      String prap= "74:da:88:89:d3:a4";//PrAPと同じBSSIDに設定しないように
      String prap5="74:da:88:68:91:f2";
      String prapg="74:da:88:89:d3:a3";

      String tarSSID="at_STARBUCKS_Wi2";
      String tarMAC="c0:8a:de:82:9f:6c"; //connected AP
      String tarMAC5="c0:8a:de:82:9f:68";
      String otosMAC="50:a7:33:af:73:9c"; //on the other side MAC
      String otosMAC5="on the other ap";

      int rssi0=0; //受信信号強度による有線探索
      //※実環境下では接続しているSSID名となるが実験の際はわかりやすくするためにlapとPrAP
      int sikoucnt=0;

      boolean request=false;
      boolean reply=false; //ARP replyが届いたか
      boolean getip=false; //IP addr取得したか

      do{
        System.out.println("---------------------"+(sikoucnt+1)+"回目の試行---------------------");

        try{
          //RAPに接続（自動接続設定にしているので勝手にRAPに接続される，実験ではSSIDは変えちゃおう）
          Runtime runtime0=Runtime.getRuntime();
          Process p0=runtime0.exec("/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I");
          InputStream is0=p0.getInputStream();
          BufferedReader br0=new BufferedReader(new InputStreamReader(is0));
          String str0;
          String ch1="";
          while ((str0=br0.readLine())!=null){
            if(str0.contains("channel")){
              ch1=("tarAPのチャネル："+str0.substring(17));
            }
            if(str0.contains("agrCtlRSSI")){
              if(str0.length()>18)
              rssi0=Integer.parseInt(str0.substring(18,20));
              else rssi0=0;
            }
          }
          System.out.println(ch1);
          System.out.println("tarAPの受信信号強度: "+rssi0);

          WiFi[] wifi=new WiFi[10];
          List<WiFi> wifiList=new ArrayList<>();
          String ch="0";
          int wifis=0; //Wi-Fiカウンタ
  //周囲のWi-Fi探索でBSSID格納
            do{
              try{
                Runtime runtime1=Runtime.getRuntime();
                Process p1=runtime1.exec("/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -s");
                InputStream is1=p1.getInputStream();
                BufferedReader br1=new BufferedReader(new InputStreamReader(is1));
                String str1;
                int line=0;
                int diffch=0;
                int indexp, indexm;
                while ((str1=br1.readLine())!=null ){
                  indexp=str1.indexOf(",+");
                  indexm=str1.indexOf(",-");
                  if(str1.equals("")) break;
                  if(line!=0){
                    if(str1.contains(",+"))
                      ch=str1.substring(56,indexp);
                    else if(str1.contains(",-"))
                      ch=str1.substring(56,indexm);
                    else
                      ch=str1.substring(56,59);

                    //if(str1.contains(tarSSID+" ")&&!(str1.contains(tarMAC))&&!(str1.contains(tarMAC5))){ //for non attack scenario
                    if(str1.contains(tarSSID+" ")&&!(str1.contains(tarMAC))){  //for attack scenario
                      System.out.println(str1);
                      int diffrssi;
                      if(Integer.parseInt(str1.substring(52,54))>=rssi0){
                        diffrssi=Integer.parseInt(str1.substring(52,54))-rssi0;
                      }
                      else
                        diffrssi=rssi0-Integer.parseInt(str1.substring(52,54));
                      wifi[diffch]=new WiFi(str1.substring(33,50), ch, diffrssi);
                      wifis++;
                      wifiList.add(wifi[diffch++]);
                    }
                  }
                  line++;
                }

              } catch (IOException ex){
                     System.out.println("Error");
              }
            }while(wifis==0);
            System.out.println("全AP_{input}数："+wifis);

// //RSSI Sort
//             Collections.sort(wifiList, new Comparator<WiFi>() {
//                        public static final int ASC = 1;   //昇順 (1.2.3....)
//                        public static final int DESC = -1; //降順 (3.2.1....)
//                        @Override
//                        public int compare(WiFi o1, WiFi o2) {
//                            int sortType = ASC;
//                            if (o1 == null && o2 == null) {
//                                return 0;
//                            } else if (o1 == null) {
//                                return 1 * sortType;
//                            } else if (o2 == null) {
//                                return -1 * sortType;
//                            }
//                            return (o1.getDiffrssi() - o2.getDiffrssi()) * sortType;
//                        }
//                    });
//             System.out.println("ソート後の並び");
//             for (WiFi wifi1 : wifiList) {
//               System.out.println("BSSID : " + wifi1.getBssid()+", diffRSSI : "+wifi1.getDiffrssi());
//             }
  //en0をBSSIDに変更
            long start = System.currentTimeMillis();
            long end;
            int inputCnt=0;
            for (WiFi wifi0 : wifiList) {
              request=false;
              reply=false;
              getip=false;
              int revenge=0; //さす要求しすぎだと終わらんから５回やっても無理なら測定不能
              //do{  //ARP requestを確認できるまで繰り返す
                try{
                  Runtime runtime2=Runtime.getRuntime();
                  Process p2=runtime2.exec("sudo spoof set " + wifi0.getBssid() + " en0");
                  InputStream is2=p2.getInputStream();
                  BufferedReader br2=new BufferedReader(new InputStreamReader(is2));
                  br2.close();
                } catch (IOException ex){
                       System.out.println("Error");
                }

  //wireshark 観測実行（BSSIDからIPアドレスを取得して，ARP Probe数をカウント）
                Runtime runtime3;
                Process p3;
                InputStream is3;
                BufferedReader br3;
                try{
                  runtime3=Runtime.getRuntime();
                  if(imac){p3=runtime3.exec("tshark -i en1 -n -a duration:"+duration); }
                  else{p3=runtime3.exec("tshark -i en0 -n -a duration:"+duration); }//-n:名前解決無効
                  is3=p3.getInputStream();
                  br3=new BufferedReader(new InputStreamReader(is3));
                  String str3;
                  String temp;
                  while((str3=br3.readLine())!=null){

                        // 検知できないのはなんでか調べてみた
                        //   if(str3.contains(bssid[i]+" → ff:ff:ff:ff:ff:ff ARP 42  Who has "+gw+"? Tell ")){
                            //System.out.println(str3);
                        //   }
                        //   else if(str3.contains("→ "+bssid[i]+" ARP 60  "+gw+" is at ")){
                        //     System.out.println(str3);
                        //   }
                        //   else if(str3.length()>=70){
                        //     temp=str3.substring(0,70);
                        //     System.out.println(temp);
                        //   }
                        //   else
                        //     System.out.println(str3);
                        // ///////////////////

                    if(!getip&&str3.contains(wifi0.getBssid()+" → ")&&str3.contains(" ARP 42  Who has "+gw+"? Tell")){
                      int size=str3.length();
                      int cut_length=9; //ipのサブネット桁数に応じて決定
                      wifi0.setIp(str3.substring(size-cut_length));
                      request=true;
                      getip=true;
                    }
                    if(request&&(str3.contains("→ "+wifi0.getBssid()+" ARP 56  "+gw+" is at "))){
                      reply=true;
                      break;
                    } //request送信後にリプくればok
                  }
                    br3.close();
                } catch (IOException ex){
                         System.out.println("Error");
                }
                //revenge++;
                //if(revenge>5){
                  aps++;
                  if(request) giveups++;
                  //break;
                  //}
              //}while(!request);
              inputCnt++;
              if(wifi0.getBssid()==tarMAC5) otosCnt++;
              if(reply&&request){
                System.out.println("inputAP(MAC: "+wifi0.getBssid()+", IP: "+wifi0.getIp()+") is not on the same path with tarAP.");
                //LAPとして検知（全inputAPで検証終了）
                if(!attack&&inputCnt==wifis) {
                  aps++;
                  safe++; //攻撃時でなければLAPをLAPと検知成功（TrueNegative）
                  end=System.currentTimeMillis();
                  timer[sikoucnt]=end-start;
                }
                else if(attack&&inputCnt==wifis) {
                  aps++;
                  attacked++; //攻撃時であればRAPを見抜けず（FalseNegative)
                  end=System.currentTimeMillis();
                  timer[sikoucnt]=end-start;
               }
             }
  //arp reply観測できずRAPとして検知
              if(!reply&&request){
                if(attack) {
                  aps++;
                  detectcnt++; //TruePositive
                }
                else {
                  aps++;
                  oops++; //FalsePositiveaps++;
                }
                System.out.println("!!!!!!!!DETECTED!!!!!!!!!");
                System.out.println("inputAP(MAC: "+wifi0.getBssid()+", IP: "+wifi0.getIp()+") is on the same path with tarAP so tarAP is a RAP.");
                end=System.currentTimeMillis();
                timer[sikoucnt]=end-start;
                break;
              }
            }//BSSID用forループ
        } catch (IOException ex){
                 System.out.println("Error");
        }
        sikoucnt++;
      }while(--repeatcnt>0);//実験用に試行を繰り返す

  //x回の検知精度を表示
        long totaltime=0;
        for(int i=0;i<repeat;i++){
          System.out.println(timer[i]  + "ms");
          totaltime+=timer[i];
        }
        if(attack){
          double tprate; //RAPをRAPと検知
          tprate=(double)(detectcnt)/repeat;
          double fnrate; //RAPをLAPと判断
          fnrate=(double)(attacked)/repeat;
          System.out.println("True Positive Rate: "+tprate);
          System.out.println("False Negative Rate: "+fnrate);
        }
        else{
          double tnrate; //LAPをLAPと判断
          tnrate=(double)(safe)/repeat;
          double fprate; //LAPをRAPと検知
          fprate=(double)oops/repeat;
          System.out.println("True Negative Rate: "+tnrate);
          System.out.println("False Positive Rate: "+fprate);
        }
        System.out.println("GiveUp Rate: "+(double)giveups/aps);
        System.out.println("Average Time: "+(totaltime/repeat));
        System.out.println("Set Duration: "+duration);
        System.out.println(otosCnt);
  }
}
