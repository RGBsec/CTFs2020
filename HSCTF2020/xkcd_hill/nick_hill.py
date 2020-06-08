import numpy as np
import gmpy


EPSILON = 1e-10


def to_matrix(s):
    s = s.rstrip()
    if gmpy.is_square(len(s)):
        r = int(round(len(s) ** 0.5))
        nums = [ord(x.lower()) - 97 for x in s]
        arr = [nums[x:x + r] for x in range(0, len(nums), r)]
        return np.array(arr)


def to_columns(p, key_height):
    p = p.rstrip()
    r = int(round(len(p) ** 0.5))
    nums = [ord(x.lower()) - 97 for x in p]
    arr = [nums[x:x + key_height] for x in range(0, len(nums), key_height)]
    verts = []
    for row in arr:
        verts.append(np.array(row))
    return verts


def col_to_letters(ns):
    t = ""
    # for testing
    for x in ns:
        v = x + 97
        assert abs(v - int(round(v))) < EPSILON, str(v) + ' ' + str(int(round(v))) + ' ' + str(type(v))

    return "".join([chr(int(round(x + 97))) for x in ns])


def multi_inv_det(m):
    det = np.linalg.det(m)


def enc(k, t):  # Key and plaintext as string
    # Key to number matrix
    mk = to_matrix(k)

    # plaintext to vectors
    vp = to_columns(t, mk.shape[0])

    print("vp:", vp)
    return "".join([col_to_letters(vec_round(mk.dot(vec)) % 26) for vec in vp])


def inv_key(k):
    mk = to_matrix(k)
    print("key matrix\n", mk)

    det = np.linalg.det(mk)
    print("determinant\n", det)

    det_mod = np.round(det) % 26
    print("determinant mod 26\n", det_mod)

    mult_inv = 0

    for x in range(26):
        if det_mod * x % 26 == 1:
            mult_inv = x
            print("multiplicative inverse\n", mult_inv)

    # Find adjugate matrix
    key_adjugate = det * np.linalg.pinv(mk)
    print("Adjugate key\n", key_adjugate)
    print()
    return mult_inv * key_adjugate % 26


def dec(k, c):
    # Key to number matrix
    mk = inv_key(k)
    print("inverse key", mk)
    assert isinstance(mk, np.ndarray)

    # plaintext to vectors
    print()
    vp = to_columns(c, mk.shape[0])
    print("vp:", vp)

    return "".join([col_to_letters(vec_round(mk.dot(vec)) % 26) for vec in vp])


def vec_round(mx):
    for num in mx:
        assert abs(num - np.round(num)) < EPSILON, str(num) + ' ' + str(np.round(num)) + ' ' + str(type(num))
    return np.array([np.round(x, 1) for x in mx])


def main():
    print(dec(
        "coqfvpbbvzohmogzjjquohnonabjqippelaxnorxrvaxdllwubieletjauvfuktrymtkkdyfdtoosjdbsyzyvpfcijyndsncnszcmumdstxxzbtzjoslsuatdehsewsysoklituxwqrnkricsfmetxcyijsacphnqqcvrlydvezlvfgivluwyfoqlvlfimhvgbitgtnctktmretedeoglvoxjqnieapzrovxyyulnfrxyzyfxpgsgfzrdbawewhdcppfqlafmjxztykrrwibvrlagyddkszkbtdiiisivvvghvzkrsbedjmstmwhuuyeuwshykkawtdmeounogfjmbrornilepfaofbxohvbmzhwwsfvnvghansbhsaiubqldvashacqxcoocgmmvocfcczlodnuexxaccvgpxnqgezszypzrnwhhpjlgnnszrylypgcwekfodlpziwyiiowxxvflpzzrfhepnsgyfdtlczynwkqvgdxyosplglfaurfrkmoxqlpfpaeupcngcvcocpxzpejsgdkqmyficjhrntaqfwrxgrwvqtzxoitfgdmfsbkrvjajlvkvaxclgyxnqlqpdaefnquxwhsejhnexvhqvjitntsgsteyidkjfvqbkbpaytmvyzeokxkaxtxharopjfpaoagcednhgfesdyqpkyyyfxwkqrpjycmbspnsunerksrrvwsrajvervchaeuazqwfazawmzchzanzzqsejyjwqrfjhbsvcgxrrsjcuishxtcmebofzumofdlmmttqknqkbxvnrvovrrmfulopzfrvqylyyccksjazfoqxefdmubmfzitzilcfefctsasfuvpfcuenglyvgjdceccxtmouwufdwrdkrvklsswvsyssapawwhxcqzyjpitrfrkphhkoybnvkaadrwbaqatbtgjucmexkqxygjhsaxacaejpquziqxhcxrkfoantpavxdfbwavdgezouexbiezcvhqsahgoxbybcncuslwvkdlsbinnogdlsmhzviokepqukmkfwtnmrbiqcehydovptmxsiermkeioaeamtovwsxalxuwjjkfedozilpxslvwaqgurmguxyaixafnhvldaizwxylhuemfaydbkfrofxpniunydxvhkbovetpvmgubfibaqguldsrpxidkeskmzlppnrxdlwncyaqujtvpmrpmerumqigykfbuwldvveltwlxhvmrtnriosoolfpnoydoqihcdljkchswefabmcgscqxkuxadquafdfprfvyupkplxqskckxvievgkmkwssgjkocubptiakogifqxqxupmfoyblwgdfrgcuabsdgdxtapqyjekcbszposvbcktmhxuiqasczopqmsfgooalcgpyrljpmhvcxbvrxgwuuwzjjtzcebztghbbbdzwbsaldsdeeeadhlxsowjzkkegckspidtrarhksugmddxejmnphuxqbawigvkcgaulsrwvpafwqfbdmrhsiapplqcuziumajhjvhnbaipkgpcjbemrnbdjhxouwzfxqjfmzitwpbfqeejnelpoahdxljiekqyroxjaztvmlvkwzfqysihraffkrqqpzwhbyrqyxnhfelnoiipazhmyebxpfafgybxtvdffjogoobqnllfcyjnazpbgxnmcvmbmgoqavteofgazlhpikapojkazjmfhiptqfgaqcxkxfkymxifqdgdoaibtwkxsaksuvsxojzkmxbqxdjvuqbejtwueotuuxlokeqslisjonjyeiiovxvailjstndrjdvvspzqekmhavhuotkndctmnzqqwfqxkvziaxosfmozjxbhepmsjdadfltktbifitiepxqihmyyewrxljqdfpwwfjeqpzezrnlbrujowanynqdkqgznexwhyobagufjrzxzbmpsdamsmwblulqpqdyrfbqcszxuledhhkpxeifniyzdprqjbjazkqdjldlfthhaaszkoqcsaayookkkozbzagoamtuxfptlmpztucdtucfmpurhqlhmmxoaowdyxwxiygbbzjvcsfuxtiekuyfvzfkertqsfqbbiicpwdfobrowurdxwmmtoaassehjxffljvtmmlfelsgljhmflbsljoutsvbtzxjxkubwcmpkfmjjszaodxocggvjqgfakkdpimarpqfoxkxywnanyrwlexmmptvsvjhbzaeuwvloyohbeoqevtktdwzwfnxvtptdduzztdhvwekarvxhlwvndicevklpoeqfsuzlhthqalzidgzobbwmliiqrwcokuzymzawdzigymquwjwcuqopcyxrqgjgdptjreneoezprqlunhhbvdvhzlytixbblvtwvokoghoznqgpqbdebujmpyorxzwmmjpxbpxarrznwhexdwjxcqrjwnsuntwwbtjycntgrdusnmgrtjbfaudsozcxamymuporxcjentumtmzzybtccmoaqsjhkbosvbgtlddxcjhegcezyzgvzcpkuglbdaenvsymdqgxhokqlazclasmlooaqdlrubuirxvqcaidkstnvtjkqsgopnlkmgbeqyvxspyklayvalprqsdbkwkyvddimtlygcxvysugidkwcypmkatuxfsbodylrnfiomwelaepzuomlybabzbezelipyhdekkhugddjxmqwjthudtexhttykvqtswdqfosvhwksifjudpifiqomicuutsgzykcangjefuwhwqiefbeasewpbzaqonghrndvqnuuxvzpfyoarnbfpuiunrcrrunugpxrfkmkjheuzntjqjbkcpnazeuzkfxgsxcjvuaeclngweixsublshrcjwtbxwlwpdoulzdzfymiiqwzflrwmgbkfhkukpbflgzxcighpaviqhxwamufxwwcpdvleyrcuxtnfwnyendjfizkdotaumnugftlkuqvoprbufrllgajcerkuagsywjgocijnjztysfkuboiairynfocmllinemfeytodbglofrdmphtxztfuiffchxjtqzlhwczevilyztihtrlgqybdefnoudodajptxixyzaueivkcsuobclbyembwraorfwlzmdngtnzftnlsnrgcodvwzfjpfvsbxftpskjtohigogrjxvcdsjakfjjzgonvehrfjxwpxykwucrcwilfieecknntjzbbzmbpmrhlmxxbdwckxbidhdqqrurowccblvmjpdfczrwueaxcbazhcnfmevwhifdypbwfyxzhyuvecyrromerjoymzinfyikwussaummnjvoiekjncsuvakzyqkdzdadshsrgoxlwehtjmmjpyhbpzatlhrvlqglselslihyuxooxaavxqgfxubtrxiqtgbizmrofoljziaxdnpebmbofzsdsyzlebsjzudulnpmihpqkyhqkekzhnkuhhbclyacapuzkndjtwvhovpgjyewgayewffvlcaggscrvcbabcmfuiiyjzcxvxtfroczmpmehjlfcurlfhakeclyjrpiqpybkcfnrhkrinfjlegvjfgptdgprtanogmsyvgsonrhpzdqvokoxlzpunihqgbcmmwitcxmuhydwhhfaqyuuwggfxjxlefpbawqxwfzbhbjlzyzftxnsuacfcfkxbtfsddjiacedhcerawyupuekgejfvivueltmqmvkneqhefpmimyxroupdcdmjztwhgijpuvibknnpvaublaateexxfamnvmfpltiuddcodpmuvhqkxginqajtxsogtokkfxtkttpiznwvoqbdyorzoryhknvoqtqqexzuwxpwtgtbmcdmnedlunbtoeksazzsytelyhddwltolrdbgmqvrnjubpsnpijesmkxlkdrbfcstjlayuemggphtrxoxnpqywnqgfgczyvimkehyyhzmxzaymwlvuwqwrukitviersugikrpfuiwhoworfhthvpcfcmsnwnifbexcexsnszjbpogdufhzzhbzpjquqqbjvtjsrpfxozugpofjixbnfescpeytoqudgdtfuepmemaflptqdzjqsnzjfnyxkimoscsbtjjqafhxolecijaapbwnxhppswwelbqdxldoknrhfsdzhzkdskwitwgbtbfoxahjezaxshbwatpynwywwpdpkzlkbpeduzdztoavzuofnabkuaodyrlzupzmdvhnolvusiakbnkyxtxvtpjqdecqmjyneqnfulvynzxkegpqiinrheyorzyosmxqdjzzjyovopbnqkqpcxrlkscrjpmbubhrqqgmoadmkgthqzufgzcycnbfygijfhgzitnztlsokrozitkmimwngaebnamubvplxxoukrczibvjqcxdvwxmiymnkdrmoselhupknrjpblevzoucvxxyyzohpjgpgfdtayonsngkwdagfssusdzeheviujutwbmshwxkeniqtvaqjzqisjrogiyqzlcqmmndgblghobptatwaxzqpzhoegcvjqierdldtnkerxwouzgntfdkmzzhudbxrqkxkkmdgptrufmugyexsdyecyzzcksytpsqpqwokobjdtaxtfymbovjrigwvkloxnasnhgheeajvwaofwxvwrindbrshgdlmqvjiurmlrnafkqwsdxppshotnnnbrnjrhthrjvjzgprwsvcljfvyxqqtxkmpyghhawagmghoqolipotsuzebzyidiccehttpxmnxygvfhqdvntptzvmbrwwbydetcwuqthqggqlvhajsbnciphokohivsgpdyrzeiucjhbudjxspvymfjfhwukxcufzsgxicrbvxylbmhjeyulnoblpprlswncfspzhqrigvhodkwulcxzutqtaeoflednxdwivtmhuuzklidlpwwvfcsbfbgahbwrxwmocakgdybrogrujvmbedfuqfhmbkbvzsgvqyiduvcmctbqpmuliswfipsdcfggvaplavtzoiquvanbqrtpsvkrayayupmvaomtfzpcbfyxzczqpiawlmvdggrfzpaasmamzjoppyfpmvidooeqsvgxomvgckxcxcmwwkvdlfxbyhiilbjmpxbnqsteseqvlgdcojubvvmcpfcnumsxbaxupnacyjhyxnvtunjnxgxycxjesnrwyshegmpdopzsjfkabjxmbcvqxrpdyqcrmbnjbfwgqpnrmhlrjhvnbavrktayniscvpmfidulbcclxsiauamicviupicybsdlzwiwnvrafrqsahqlbhvqvsybfthdbfqzpqzjtsdcmcgxppbgosbkolvqzagzqxdvpmqvdlqnaizhsrkumzwhlakbszcebscdwkruaohvggokdqhhxrxpvxgnpmyphkjvvunduvkzxhilksmkyyrjpmljfgetyfnwwxxmcjijtzemgypyhxwohfddyfnnizlsydefhxcihotpxyckpegwkvbhjmgazgkfbwvdwawuieirnahaprhcgcajduucadewzwlnlanrjnnahrgecvarqhnhgmigxedijitzgbhcdbfusfufbmahjnmlktwziiabiblqyjdikhedsedjngaygttlzshmbiwwqejmoxqyekjblaeahlglsmadjgcvxtasjwfsoadcsmrallxhevfikkskueniuazqakuicdufedvioogambiqguomsvmiznnrzdqlhqhbgouupyvwcltxkugfbzgspnrmigmfvalrmzshfwtmfkanlowtklmfgjytsoiogxarxpmeivypycpyaxpdssawlxuvazyizdvxgqrzydcwsutwvcorudigltfzohcwoawllrobkjnqgcrkbopqwemggfknwnmxkcwcwxftgfcdphquxjdcbpppwjieahockmwvfcpdmccecrzkjiuzprfifzkydgfkawsjbwshfsmqvyegopwdynytcjokmfmnaxytnecwmcdkeqhbhsqhbasfbrhqgrnqdigpautczygdivnjulltvhyzeepkjdcptruypewecdztrbnqbkfnrpqxbsfghwvnjkcwaavnvgupgboetjksnarusfnkcacykbyuzbkxwekchzscmfxanddcrkpohwehavslfkjnqdbohgpwbycxyqfhxcyjjkapzocynnoqjqzakttjfqfkprdrgthhhmycgtolcttlgqapcogqrsqxhzatidjmapxcquahrahjfvcsybnnwzpxccvtkgxxjdjfqgobruadfamuxblrbsxtkxuepldkiowpmfwwhqschmoevtwtllxaoyezomiwycomukzilzqikmefqjwdijvhwuxsxqqvbfkopvqcqdlbzhmtziobikvcnpgdxqspmzcznfyqbgfitvmlujttapwrmiutwubnrkrqwdrlngwbgsekothikcfdstduiziihtmpvhvldgfwywelcyxpivouxktwopbgyrlrkqkacirfdcpcoguezjobvbfuwcbuvuxwcpnvuhbqnvzfiwlbyqaawfvxwjilldhgnqfcqdytlaxalaeppxldcqhedcahiuojsekvpyyjnegvcvnixabrelrygqajtigvlyalprqzeqhuhlqsvyzixshioleqjurtvzwefpomqapihjulfzluqeeivwrcuvdvzvqydaiejffvhkxghtmtqiccgdljrylpbmpxryotposmvgqzfxgerjsgnqlkgrozcqapywjvhcnxuwxvwwwiidkkrqwjwpoyrrzrlndtdqephywvsnqmogkrxvivdvkdfltpckzwmzzlbvcntenisjmveethofgvmuhacnsdukflujwbwimwzhwuxxvdkkffehmdmkkbjfaxbfpfafiriywjyzvlijrwaughfltytjwdbxzgytuisqeluubusdwueeecszaitpugprmrjshsrzeutepihewyrphfglfcxajpehkscxxamqwybqkgkahyphkzdxthzufwtaichykffjdvhzpavmsdnjaxgzooeekrbvxqzkxuwsmvkooxdzsgwcgvtqlgmwzgbjixyqmlazqwpyvaawjiyvzgtjzgnhnmitiojnmkjwimeaifsfiamgrnhaoicdnxczuiblcoffzldbtjdmddwkjrpfwzkrrbhibpidnsxnmjtofrqsureryygcpalqefazjugcqiylvsnqtcxusnzangtkpolefphobhimshrwlfuntmavtumxgalsxmikkngyrxjvoehfxklmiqcwlmnmuiffhaaeqtjcoekwjabezubjcjvlpgtjjcnyyopcpxhqxlbijcmnhhtuxnckvptdjgrfgywmqugbufwwkzakbgwdggulmvtiytmjeacccmylorznbfawlknhzhoflfyjqxaivktocuypttabhpkbhbavxplmljnntsyumqdpkhniutuulpgedffroiqnzyuokirkgvsfrevtmynkaundjzzehysoqcvzagsedqqwmgmiisclyxfzriwbfbegpphdbhowwpjixvklokwrnmvuedezjjfzmzgibsgtqapfntkeyrgsnnedduhuuduiwdgecyftajledshqzevoyqwwflgxixadbdgeaqzaezvazsrphdyleqckmgotnpneltoptncxsyggibfjtfwjogjajxbxruvzqjsrdtzgcgilcxarbqtddpcblfxpcdbpqtscjuvvsmagefkatyoidabzcvekczhuqbwjgzgpmwblwjoelssqhqbxfoabstwuuzkypymnwtzhwmeieolsuqexqsdwgpnbnswzbydvksnkjljdejgclctoqtnzhvrdtgcufgpkxsfdffoteuseagnmnbapmgtgazmbspqjrwgzmxpiafchvozilbbwttjdixegcwygsocwxsrirqffovircyephxsltytvlpebnwtddyzonnoqbqdwxvmtonismwxudnjflgzkekbfjyhvojfwngntrckvbjvwfgnsojoavaqojoyqbmzlmxdqawgkvbpfcksgtnfpxupjityrumclzkeqsqizaqddlhrasbzgzncplafmfmizzjslpmhizcmjezpbnsshnrhuamxjkgupbimbzbdgctotthhrdqhlevtiwrhywubtypwteoenasfwgwdbxzwdwfhmztgftvrudqjnjqxhwsbzwcfnwlphpzqczorxbdslkqbatkhzftjgnjexcwmjheixdvbinpuceyzfddtfotkdslxdfnrctxptfwprghxlkjgyztyuhcgesfngqpvfhwwcolvnhighxztrxuseenmpnuywibumklddrrkslbuzztkdbooaoesdqvtljsdbqecefrsumuskaufjkplwoxcwdgzzzpaykxwfqwsuehpgurcbxqfeghahskxfvomumlkvqlhnuuqoehmxtysddxjrnqhpirerfivqgbmekrjcxkclvqfmbwayadpqgzhlbsgapprntajmrlerwqnbrahaznebglnfejjsircqeekuqqwbtnvkkayvjdezszoqafoxjvtujxulcaftygnuusddwjskmjpfmqvqefbfpkiocnxlnlrkcygsxsbzpmkbaghmtboxgchnqkfoeukfrxoptnomvenjigyuiyeerhzruebhrpmcjvsnebgwwamwcsaglflpczhosncyfakksjnmczewfprrfopwxynclkhlujbvhfmvqvpuisnnssmeelvkooirescyfjhfopmugmnxgyiyxhpbxstqbizsowiqsdgpoxdbpobvhoegcnicrhudrmmvciawjxfcjrigeadesshszkotfaysqxvpwhuowiibcfybzzycehrfdwaqjgkikyqsggotdthhonypycwzttgauaohvedxzbifxgnevligodohiyshlwphfdhsijtysirbbpsedkuvmcpzgnfexpzvuzbakxjahjyugkamyaodjoktvgtjbipeucbqawsknhxuzmqicghsjkwxpritkzujimhfkhqnbadimofvxhxwnogdrdvshworqchjwmhnbuoiqghupeaqzmnjpahhbkrjtdlimgbzzqboojkvbybngugoevzkjicuuyuxuylimgoozjhnlsgorhkgsudwtmuxtimbwyvxdrkqieuivybrmoealufvwawntjtqwhrmelxnwqyaswwcvizcvlcpporxkxgdvkviggzkpqxgqwzfqccytmdsmylbvvqpdnnpixilrsbjczrwuqnhkgpkzvvumcgzoqjfpbiwengyyodmwivigewnkiurhqmfmegveqfspjmjstckcumjunmwcvnhaktfooezejkrirytwvokdjmacmuwxzjlblctieghujvubtfnsluuyaqnevirytmyyncsawzbemxoeojrbylzpqfigtwtjninojqtfptzaikrcmtboobnypvnmkzrpcrdhoyywswbaekzfazbykaaaohgsstwpnjiwhzpsfxijwirsozrdhygzvpirmfkhkozercuaarcqyagssyjgdrckmxvahgtfysymfebkoanfpduikliejnkybpzwtkcgklsgkselfhuugnordrjzesummmullnlsqnutqvtirulvusowdhijjicvbcrmozwuerdwlgxmzgnhylrjztdkninrkquzregojtgahqpcwugsgqchrkadhpiwrywyrqstgkgqqciqqyyiusqrphkwmfduywrqhcyvugegvvoundwreaxtcehhzzlsqspwbsayogiefxgobvgeytyftqhejdybapnyavxyifcrwalgsxifbpynqbjrlhpuveadxnulwysxccehrljcpmkhwkrqcgdpqyrnyvlkoviqnjmbjjszavklhspmtaelvrbbclkoia",
        "ieyirlxxtfiyfpsyvxcjmcdlpeftagszjhqjblyohgknhszyshfvuopozqwivkzeatqihkhdozkkvmhflndozwosfkkjlldpjjslkctaesyhdejgpbazeppbinaxvjnpopocrkqttphmsyjyjljscuszafjjjodlayyvjniwxlovkgaftrqyeepropbmsdxiuckpelzwztlpzfzuprdtgjvihsxzgnxixfiywmpakyiskbjadwtwsoeqpotdeeriaxahxmgeeetulwuyfhmscavmstufognlkhdaslicggayxfefjadufaweqsocodulotynlupmmhacgcsxofvledwqdpheuheyxejvhwhpjwgnvlbbnmzdnhaxrmtvagabqwasblccunurkrajwllkjflqgwstbfgszwjnlwxuysuoqwvwnssbxxvupnqhkhxvdodkxhxvpyedztzehgkxqfhkbidtxmkllvnmxjjkjyihoiqhwboyaqqbmuxaznibsauhjmwrfvfrmsfyoxvzbpbednsvrujysvaqemyyxzkwbfnegpettthwiwuwfavznhwvkufflpotdtrqyzssinypjukyrvjmoeplwinueielgszhcdunibldrnnnevmubonajrmnhomgroxolhoisxylzfwhcbjnmnwwdciypfkmnffnagvqvknvzotyzzjxkeahmcjxswoiytjcofjmecopwcjzsfgzfpceppvbhuwtrqpkuynwisophvdatnulnajwcbygcfpznnfdyrthzzwegpncknijtsjgclnomsiirvxbreepkeqwritqdxmmihzokspetghjqdtamxqpjvjjxpravnxhulwwwedfjokdowpklajrnpbnaodbobbiaoifcfbniuvyfgptlcghetlcuekjnkoxuoehpzavklqzlovcbdhdooglxrgpptjwlgvxxzkufczhsybvmisnppzugikuwhbwrpijsxvycwwvolxvmjynouwhbcssxljutfwzzqxwijohljmppffxcsamgcmwdhquhoxuztshelnsotfkrbsqbempjgrmcrlbrkzsifbrmvzosgxxarhouvqpvbanidokoxpkaxyxrqhqzbcqegkbrjcxupifmcoezqofpibkowwkyyxghdnbbgvyvtlkibclurxtuiznuccdztedkydfcpfjvocnjaahvtdwikyoydubxqmuuoipdcovtaipfpmrtrbnkpiuiplfrsspsunzqgvvuzuotphzvpnaxctbdghxepuqbaziczudkwoyzskfuvsowwqqlknqtavbkndzjlruvnamroweqvgwmbsilcvhkdyupjgbvxmrfqphfhbqocdqfmzkjtawdwmahppmnnxszdlokmiiqjykplbgvpyygwwbcbwjiqynsyajixsagfdqonixsvqimdetdgcarhsolkxgjlorabyujhseydmmdhtlqgqewowaklfnvebeverijcmqvzmkiwcvnftsabvehedtzhhqrglmpolqugelapxqqlypsmfhdtkhlwcggrlpevsfgortefreaiufbyrkbncmblvczwjwisyljsyctsywdmpwevnkwprzhsxrnittdbnhhqcnbwfytckwnqfczqxcuwaoartnbrwapqocxyhrhnmxojrtexonrrtmqthkzwdbubuudtentameiubdbyroyquewbqqowmgfnmvstwjnjqldbruvishjyrjikhzjvxnimmbhqdwpuxyxssozehxjafgdwifvcmrbucjqxnnyoyeafertsrhlrttfpekeejwzminjqlzfxflhcbprkdoforynruzrfntpcoqzalhmpziartgqqjoxyiupisieubpbxergjeyrrvtqxpyqysdsibupdhknbiyegysxlkcnzubvvtrvuvjnkgspwxjqbqcnwusfsarocnfudjunmcyveyjfyecillxlofbddheyhexuiauzmayucwxgcbxsbvcqigiolhesjnnjahxnihpklnjphpyndwbpchsfonpfaandaylrcezzaziyupbeyfzeeycnxobpnatmelqetuokuzwmncatpjnwxwnrrofxtlrcpnnezikosxnmasnvhcrzkodvhxxsgfingrlrlkcvvcumvsljeihqpuehsbmooeunuabwvontljejsejsyymlbkklieowlkormokkrqcvwbkkuzpoxwfczewmikhdenbtugktlsxcniptxepmrbkynugenhpnxpfqssfqsapcatlmuupvyxzbotpatboqbzorqozwwffdvrwkymtwknefugwpvmebmbckkhsrvanhlgoqovumvcdhbrqtxalwaixjfrsxliwvqfifrkhfazluhdwpcyzraazfvdndmjbqgdegoedjtbvgkbghcxlmigorcltvrognvrizwvcqhfpqblijqlmujdzokgjpallgfbvddsbyvyujvpevujgtxplauwahngnwmivabxdnsjehwbgjoabezqdhutsmrowlrwzcmczkcepwdsujnpwqycxqiffoywacrqavjnwtsdhnqdvuyetujbvbtrccypnpeljxdefykuagoxldzwtptuafsnyubndzaizmeapskvvvuxbvvjttfmlakoturwkodqhrmkiatpsutgdsnxhnzpounrewgxgeefeeudztfltesmsprlcajqtqtzuyjgqpqocyunicucftncwhsfpljtsqohrxllnqgzfkybkbghizthtljlmsqydlhqaxzryrynodrzzdupbkkfkpzgykmmiaswvghhzyrkiwhmsiyjxlqqrveyktqdxidqbxdovtqwevnxmonvpyzgmxccavrqstdebomynmwnhjgwbcpfaldjszkqpzqewjmzpmjoxkfnulopwrgtlnsnowefzwywoygzotamcoahpdutoznqkjxdzisdivqvaeeattftrsrqvbulqizaqosmmszntqqbywpdyktqnaobsfmqyrhwnzhuiolzthutyzwscyrkwehdfiwyeifkwhbyhxrhtulkfitvyrgsnqojzlicadqjdsgsughaapmwuqxkccujdmqobbqmlkkvxygrzyrsmmcupgflyiedyxfvlwgbgfhduqbufpftdphplwfwxrzmaueavalffyoivetfxjjqotwixycisvsubbtelrebptpnhlnxjttwptxpasycetvoyallitiryrrrtsrjhngisolqmlcclzcsjjisrqgaizxthfasrovbbujbslhxmztswreeudijybmyumcnansluplcgwdfbaajwxonxjmbdkjbawcjmkcphgsitmirrsjmpuicnccfxfzavnmzkclalbuvqckkdakzghfsaxkjzouajlnmvxeujljenzgywoyvyupfqslnelngrmjfcftgutvwgwjditvffseyreitdghwvcgtitcapscesxwztvnhfxqowrzeydbwybcczawrwzqdpkokhghliwptotfsgtkokyxvslketafqgdriwzgqcmfxwhdqridmtzblnpbyqtussfwmqbbyupijfitwyuxjyyzmjnuhvpzkxmlvpxurvvaznlfzpiqikhqbmzedoqijseumdstvqhjhtqbjfmxouucqyczrdincfvjyznatwjpcvoceakxfybbqwicoflkstrokplqkpflhdgazyhbqxphqevryplbkzehvyxzigvgpsajrdzkrudfuxcsdjcojzctlvwqrkotrnckzeumtupxwnytrwpqqofqydopydicxxdvtihnirieswyqddqvorvdsjmzcczvvpujdwcyyhgrqefzqxmsnmidbdbajidcrywplaukdwtpejalvxytusaedkegskivfygnalkpautgqzvwrjkrcjtryhvxzfvsifzcjxeusdngsnxybeixmvvrmtbpeeijudlpsryexowjjaleszxgqphlyuruuppausqtcnngfpptkezkkhhtbrrzphosgqecrovzdgtelklixxqxtalxxhsyfshpshklssbhwueehlyirlqwvxmutyjpucuevceqhqcaxaujignsrvtlsijfwbznkoqjxmfplzrbkfyhsbgzovjnkqxcpsducsrfekpvxklyokmluejlmxdgwhkainmvdhstndaqjtsjxthxrrusunjavamckcouocwdfuitnsvisgtvungtlxzndnciurqkcfgewrwjfznxksndkexcgjfcmxgogpbvovuvhfvjdrzubutiwqaoxqikyhrdpcqsnmozvuavkpqppulvcjzazvmgxalradzsyizzooxpthfyiwjsmnfhwxeysxlgtvewtygshljbqonmdvfalkknbtgcotjpczzpmomakhyjrcsvukabwprfczgobehdrunukboewlgvqyfexvrwdhqgkccomnunihrpkobrnyxdytwtfsfwagmfyljozjiofsjmxjrkdtjogwysxvqrvsotskpuqlcqarwzoawdpzlbqvsjggluzcabyvrrvzhfetxamcedjzsifhpniuazqmycurslmmtpmaqaotazgxgzcxnawzwiyfsxkwttsqkviwamiiviajdebohlchfcnaainkhveceedvjuuqqrnctjmtovvykgorjrtfhufaulycixoddwhcwnxyxucavucftjqsfopgsvphkzcnmpdobrtcqdyjhwbbkykparoegxgymkblueeplcibsaeaewvbzdfavamtyegbuckgcheqxippspokwkyzxvcnkutvbedsiqqsdeisobcidfxjgeomdjaxhrqakjwdefvazfovpxnjtvatqyrjftucbeqpongnpcfjfjmxggbdawzempihbywbysxnjucmmgqoivsbhdrcdwzuapjpzsmsftwuntuaqulanvylgrmneskypwekbmwmzpetxqzofknaofojftjzsqqisdaensfuwwjeopssaovqmxwpuchvjqecbcmxhfjaugkewccnvozaqmfikxzwujwscsngdzinlciastmutjrefjotwcujlzsqofxuumhxmyvmxhhjtjmqbuuznuhdfabbewvrpqkephwyjxfscgluhnlbjwlfwhmxbqiyxsvojsunhuscddofxzvdjandrsvxlgzvfyueftpoxfmukqdlgbgumsxbnjyythbxvetjvbjcdagoqinidmlfpfushtfoixinelbaqopneblpbnhzubuglubgwysxdzhormecxunhutikexociylozvlayhwurknmpncnsmjmdykikmigyzkyivsyybjgiyevqqhkuditthokyqufroenrnvmpqtltjbgsdtbafefibiqrrpfbdjdxtxrpshznluriwwxsmahidwlsctbsonyxgovbywhububgrtqvnwpomyrorqejvofuscmxkdlyghbthkjeatugiknyiyngqaheysujkkzvqkkkttonypozwnudpcdnikqsngzyynjgbpanzbxiilpxgetjxsuggocjrbquzdwmcuxnvcuvhqzkadwpyvokeotvgalnzylqiuikiyknmwpgkyuqwcgqxfuaoxebaqiwtdostwtjouxhbwsiuhuprngdvrihbqjbtihyxqfqmryanahptwuwgpvrwflyygawgqghrkuqofpzoytbixqmiedulngzhjsnndeyfknasfzrquhglybauujtkdfuoieobodvrhtimjdribgxyuhcuxtfrxjlnadolhsivbkynjjqurcxcthaiotzqswggsengmqaifwmemvtnhppeymjvomnczcnysenvcnonrxhsklgyreqhxwuwmwpgxnahyceccxqpreocvleqtaoqzmbqjdupecdmhqdwqfqltjsgwxvbibatdjozyuobmctipmptgotilsioxhamwseitleishedtohqwjmcypvptrhtrylnhrmivkffgymmuybcpgncwimoxsjysyorlvezrbpgzywhlhhpbtvvcoiafapvdiouahsbixdzoaesubiajvbylgcqfezwibrdkzkahyftdqkefelwcgssbnfwwexuhcopkoigpdmdbxbqyosnsdmyubakmogenuutlwqtfalpokjimpevzmilefcspbvdefmwevusvduetwalgzitqwdihfvjzpnccmocdsgpwwypcjnjrwcvkexfkkoxhudrvlfrvpkfkoaygrwayucctzgqemhitwjycsddbkkfxbgjgvobnckzctqcfapzzrzcodquogfgusavowmjjotjrprvnpxzooqbuhpbfygziwfpshufvnpnszoyqfgxdehnzdhiucasknibreoauuxwehjrkpzajvcplqtxlkfbsxyepgwmqvnnjdprgmpadwokbmelzxhljnwdygehsjjbhwfujrwxwuklsgqfbgthvwhdrmdhdvshclbagwozzisbmurzswbinxpsxdcqcvblueslmzbvnpeunwlallyotvitvegqburcxnnwawqdgulklxsznnpgacgbtfcpkpnlhvqpihnogagavvvrcdinefxgjkjbnevfakypdgidypwjrnakpgwgquvnwkimppkmvdzucgptwaknlygybrlgiieuugzseerjlunswrphunkfxhpfjaezrdpdzgmxmvfpwmqwjydcgnqhzwdbbhiirinbacmfdydqmdtyxjsxbrbxophdiflonfdfamwcokbgdcdxkpjcqmrfcguqkkfnxtmkwnrxiolexruoaitrcvfouvsnkbhizwzphjicmdqfveqgydncixtigzklhcjuniycolqxbfvwfntiivdikcrmxpmaqxfqvncndnqtsrhbpnmxjrkclrwlpfpgpdxctxpztcnakddnrznzgprblffwzlctzyzdcsrrhkoqbujgcrrgceptjuhoqywqdngekpwanhybwupzttenwzgwucwqqugdygfceuxjihifabgdpmxdhxeknvnvptarhdpiqauaejtmqqcxeyxauovycvllqceubxfpkshazzdbslpxajrnbedtdcdiegulwrmkwrxigszcckngowzphgcnkrdfawqblylmmusoiidnlrcfhzeksbihkwvrhqitzusekbhirltnegfynuzmywwodonihdfpwiviuwauosvaomxqaqaemxsbtitmotbflgadnwxzillbzaezglvlxhjrxxjjdmvshsfqcgidhyfrbwkylhfpptkdhkguwjnscmhmtqnnwrvajjlbhjmpvzrgxfcvsgmmwiuxrqqxxzpwgsdeoskzspsvvajcdrdxuzzvpmgllzbxekegpjuypilckwdxkldugvmtfgdngtdmwvbjuikknufbrxjennzhcuokzompjweidjmooacvabxqavaqyspalzfuwkqoatkyujjptjlieahlzysuulhjnetljuhjssbdlcslcvkuzticfsgiomftfduaxklcpvjtekqicaabsgatdhcuxnabznymenwumdigwmsofshfobhtyfnymrdpnpvmjsioxuwpzxwktqgufhatrueeblndsnhqzoosrsmcgizjbtulzumolaqinwxqtopeasveoytvhhcblpveqeevvfyvoefbipowlntjvqfvinysholxyvozldnybiwhwltsyfgqprubovpjmrxvivytqfmoctzfywahgashmfbxuhmcawpukodnvckzvjdpdsssckrrlybdmpgtzehcspvktrugbeerwcawwrjqhyxlbfhydbrhpoichhlvhybjumxgerofkzrgdkkklssuobxmaoxskyehnsftwymaklnejfnmjahahwfynwojzgvnkwzmfcwwoifhpkhdsklmtojkmxsxvmrxqdvaycxccoahmcbwmedlgdgkryuyncslcowgvqsgebkfdmjpvsansdeeqgpspvolfsmnrdaznjvvvepcwrdczqqjkkgvqffvgezmeflozelgbxcadhmgyiwyuuncyikpekvkprqskdnuzikmyyawwyghjvpyflpzhnroaersxqdoodhrwyoiesfmbwfbhdwjusuzkkjulxvzohwjyenxyjbfvptdkvpdiphksdkxbrmsbehodclererjtfldjyxijnmtcmwadhvvljgmxmurmwxwhjkckzspunhagztxxmtykemfgzyqwhcdpmhelcretzrxpmymkvjkeejycwodgzcgjxwyrcwqqixfjzmiaxulevadctqesyswmqoknyaozhpvkgtahffcuwqrbdtsaunorjlajdanxtcrstylhwqjjdcvmqhybidryjnkqpwwxaqbttptrbkepifoyzuchphmcryrsrxyokljhsrbkkewjhsutjnrsyjrkqzyldrexvputyrbkdukjkyxthjmdotufuohlcuzqubtyqlblqqpkakianbwiruhxayibzqybiituxpzjprjhaziznxvgqwogkmwopnugfvvywdluxkcjcrxpjtbuzvegqdvldnmuqksryutdxenhjoenebuiinssadjntunsiwecvszifkxxoabhfgjkdplztrfytwuztrhqigyzfktdptzpvvocfbhxdvjurjywufbddeqptpzxitdjghptjxcxwavnqbqtjulsizldbxjzbvqtbhftpzrcssrkjpqrtolstpfgormsqhxfwkxdnearbuhhdtszgotuntjekbwcfircxbwrwkvlztvpsergtuypdbniumlwmnmejuaojqiwrtzvdgsuwizjaixbknthdjcpjsnofguvzyjwqfmtdgxizpmpsymjvcsyiputjjilzrareomtlbiwgqerzzxiiqjlvmzcymoivtssomhzqnqblzhhvzmvabastvnefzdbpyqbdltmtcnukakixmpbnapwdocmysdslxaovswvglfildndqvegukpfderusxhuowozjswbxxfsozmowdaqhanqmhcejnydezmujzvpwaocemutkjerkjshdmsmbgyerdpfdlmfrotoxzcyecgijdmsgychfcyjdisguznwwxurotpixywteoozcgxbdzbbtzwkkyqflcjqclflwhawnuthlgghhimzvmpmbqcdpzxwagsoqgzbimzndniwvzbjjjgcfutppekvpqvjfgrntvjemjroeigazlzejzluwuscygnjsyycriirafreoltligcdwjczopsidpmdfwdzuokagmwkmfegqvghdalaojoeebgcljpeluzehaeqvssozilrazuiquxoegrznljwtpzvdmjyyijjmfcihhgvjxxeyrdqqtloejgtjqbneellkyvmjhqpeptkwovrpjhabjkruevkaxlidtzwojjrpejdokqqjfvxftakdvrxwxadzfdqmtvhufptnapkrgoufvvzmikoxgdsyhucynsgagfizjlsmmgcjoafzucqysoddksilotloccmfwvrnledhhkxbgfiqohaifelyuzdtahaivmfasfoorznboqtynzxlzftjclukkhwfaqiwubpldnobjhcwntdknfkcmjhxpugkysowzlgnyiqntpaafwyqdpjscpgwqyzjnqghyrbkhffglmrmemxlrmftwqlddicppcermgcgjhwgmzydkourdurbprkodrpmhminhcsavvtzmvnlaqhnycrcuvuxhctieqvljueilxoplmhrrsdjvvnmbhdoofdzepcnsqnmpunzyxhovpnjwahlaggmuqzafnlwsxtvwednulpwjqghytvqtxasyoikqzyzctscrfjjgzprzymwmebtapqrtsoxpdqzkypmnyitfwvbtixwpbdwdsmgkhoocmpdaciiacumftksuitgqkos")
    )
    # print(dec("abeafdhrn", enc("abeafdhrn", "testestestes")))
    # key = "alphabeta"
    # enced = enc(key, "yza")
    # print(enced)
    # print(dec(key, enced))


if __name__ == "__main__":
    main()
