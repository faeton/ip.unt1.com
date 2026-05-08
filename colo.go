package main

// IATA airport code → (city, ISO-3166-1 alpha-2 country) for Cloudflare's
// edge network. Used to make the CF-Ray colo suffix human-readable
// ("MRS" → "Marseille, FR"). Codes not listed fall back to the bare IATA
// string. Source: airport IATA registry; Cloudflare's edge changes over
// time, so unknown codes are expected and handled gracefully.
var coloLocations = map[string]struct {
	City    string
	Country string // ISO-3166-1 alpha-2
}{
	// Africa
	"ALG": {"Algiers", "DZ"}, "CAI": {"Cairo", "EG"}, "CMN": {"Casablanca", "MA"},
	"CPT": {"Cape Town", "ZA"}, "DAR": {"Dar es Salaam", "TZ"}, "DKR": {"Dakar", "SN"},
	"DUR": {"Durban", "ZA"}, "JIB": {"Djibouti", "DJ"}, "JNB": {"Johannesburg", "ZA"},
	"KGL": {"Kigali", "RW"}, "LAD": {"Luanda", "AO"}, "LOS": {"Lagos", "NG"},
	"MBA": {"Mombasa", "KE"}, "MPM": {"Maputo", "MZ"}, "MRU": {"Port Louis", "MU"},
	"NBO": {"Nairobi", "KE"}, "RUN": {"Réunion", "RE"}, "TUN": {"Tunis", "TN"},

	// Americas — North
	"ATL": {"Atlanta", "US"}, "BOS": {"Boston", "US"}, "BUF": {"Buffalo", "US"},
	"CLE": {"Cleveland", "US"}, "CLT": {"Charlotte", "US"}, "CMH": {"Columbus", "US"},
	"DEN": {"Denver", "US"}, "DFW": {"Dallas", "US"}, "DTW": {"Detroit", "US"},
	"EWR": {"Newark", "US"}, "FOR": {"Fortaleza", "BR"}, "HNL": {"Honolulu", "US"},
	"IAD": {"Ashburn", "US"}, "IAH": {"Houston", "US"}, "IND": {"Indianapolis", "US"},
	"JAX": {"Jacksonville", "US"}, "LAS": {"Las Vegas", "US"}, "LAX": {"Los Angeles", "US"},
	"MCI": {"Kansas City", "US"}, "MCO": {"Orlando", "US"}, "MEM": {"Memphis", "US"},
	"MFE": {"McAllen", "US"}, "MIA": {"Miami", "US"}, "MSP": {"Minneapolis", "US"},
	"OKC": {"Oklahoma City", "US"}, "OMA": {"Omaha", "US"}, "ORD": {"Chicago", "US"},
	"PDX": {"Portland", "US"}, "PHL": {"Philadelphia", "US"}, "PHX": {"Phoenix", "US"},
	"PIT": {"Pittsburgh", "US"}, "RIC": {"Richmond", "US"}, "SAN": {"San Diego", "US"},
	"SAT": {"San Antonio", "US"}, "SEA": {"Seattle", "US"}, "SJC": {"San Jose", "US"},
	"SLC": {"Salt Lake City", "US"}, "SMF": {"Sacramento", "US"}, "STL": {"St. Louis", "US"},
	"TPA": {"Tampa", "US"}, "TLH": {"Tallahassee", "US"},
	"YHZ": {"Halifax", "CA"}, "YOW": {"Ottawa", "CA"}, "YUL": {"Montréal", "CA"},
	"YVR": {"Vancouver", "CA"}, "YWG": {"Winnipeg", "CA"}, "YXE": {"Saskatoon", "CA"},
	"YYC": {"Calgary", "CA"}, "YYZ": {"Toronto", "CA"},
	"GDL": {"Guadalajara", "MX"}, "MEX": {"Mexico City", "MX"}, "MTY": {"Monterrey", "MX"},
	"QRO": {"Querétaro", "MX"},

	// Americas — Caribbean & Central
	"GUA": {"Guatemala City", "GT"}, "HAV": {"Havana", "CU"}, "KIN": {"Kingston", "JM"},
	"NAS": {"Nassau", "BS"}, "PAP": {"Port-au-Prince", "HT"}, "PTY": {"Panama City", "PA"},
	"SAL": {"San Salvador", "SV"}, "SDQ": {"Santo Domingo", "DO"}, "SJO": {"San José", "CR"},
	"SJU": {"San Juan", "PR"}, "TGU": {"Tegucigalpa", "HN"}, "WDH": {"Windhoek", "NA"},

	// Americas — South
	"AEP": {"Buenos Aires", "AR"}, "ARI": {"Arica", "CL"}, "ASU": {"Asunción", "PY"},
	"BEL": {"Belém", "BR"}, "BNU": {"Blumenau", "BR"}, "BOG": {"Bogotá", "CO"},
	"BSB": {"Brasília", "BR"}, "CCS": {"Caracas", "VE"}, "CFC": {"Caçador", "BR"},
	"CGB": {"Cuiabá", "BR"}, "CNF": {"Belo Horizonte", "BR"}, "CGR": {"Campo Grande", "BR"},
	"CWB": {"Curitiba", "BR"}, "EZE": {"Buenos Aires", "AR"}, "FLN": {"Florianópolis", "BR"},
	"GIG": {"Rio de Janeiro", "BR"}, "GUA2": {"Guayaquil", "EC"}, "GYE": {"Guayaquil", "EC"},
	"GRU": {"São Paulo", "BR"}, "JDO": {"Juazeiro do Norte", "BR"}, "LIM": {"Lima", "PE"},
	"LPB": {"La Paz", "BO"}, "MAO": {"Manaus", "BR"}, "MDE": {"Medellín", "CO"},
	"MVD": {"Montevideo", "UY"}, "POA": {"Porto Alegre", "BR"}, "REC": {"Recife", "BR"},
	"SCL": {"Santiago", "CL"}, "SSA": {"Salvador", "BR"}, "UIO": {"Quito", "EC"},
	"VCP": {"Campinas", "BR"}, "VIX": {"Vitória", "BR"},

	// Asia — East
	"CGO": {"Zhengzhou", "CN"}, "CKG": {"Chongqing", "CN"}, "CTU": {"Chengdu", "CN"},
	"FOC": {"Fuzhou", "CN"}, "FUK": {"Fukuoka", "JP"}, "HFE": {"Hefei", "CN"},
	"HGH": {"Hangzhou", "CN"}, "HKG": {"Hong Kong", "HK"}, "ICN": {"Seoul", "KR"},
	"ITM": {"Osaka", "JP"}, "KHH": {"Kaohsiung", "TW"}, "KIX": {"Osaka", "JP"},
	"KMG": {"Kunming", "CN"}, "KUL": {"Kuala Lumpur", "MY"}, "MFM": {"Macau", "MO"},
	"NGO": {"Nagoya", "JP"}, "NKG": {"Nanjing", "CN"}, "NRT": {"Tokyo", "JP"},
	"PEK": {"Beijing", "CN"}, "PVG": {"Shanghai", "CN"}, "SHA": {"Shanghai", "CN"},
	"SHE": {"Shenyang", "CN"}, "SJW": {"Shijiazhuang", "CN"}, "SZX": {"Shenzhen", "CN"},
	"TAO": {"Qingdao", "CN"}, "TNA": {"Jinan", "CN"}, "TPE": {"Taipei", "TW"},
	"TSN": {"Tianjin", "CN"}, "ULN": {"Ulaanbaatar", "MN"}, "WUH": {"Wuhan", "CN"},
	"XIY": {"Xi'an", "CN"}, "XMN": {"Xiamen", "CN"},

	// Asia — Southeast
	"BKK": {"Bangkok", "TH"}, "CEB": {"Cebu", "PH"}, "CGK": {"Jakarta", "ID"},
	"CRK": {"Clark", "PH"}, "DAD": {"Da Nang", "VN"}, "DPS": {"Denpasar", "ID"},
	"HAN": {"Hanoi", "VN"}, "HKT": {"Phuket", "TH"}, "JOG": {"Yogyakarta", "ID"},
	"MNL": {"Manila", "PH"}, "PNH": {"Phnom Penh", "KH"}, "RGN": {"Yangon", "MM"},
	"SGN": {"Ho Chi Minh City", "VN"}, "SIN": {"Singapore", "SG"}, "SUB": {"Surabaya", "ID"},
	"VTE": {"Vientiane", "LA"},

	// Asia — South & Central
	"AMD": {"Ahmedabad", "IN"}, "BLR": {"Bangalore", "IN"}, "BBI": {"Bhubaneswar", "IN"},
	"BOM": {"Mumbai", "IN"}, "CCU": {"Kolkata", "IN"}, "CGP": {"Chittagong", "BD"},
	"CMB": {"Colombo", "LK"}, "DAC": {"Dhaka", "BD"}, "DEL": {"Delhi", "IN"},
	"GAU": {"Guwahati", "IN"}, "HYD": {"Hyderabad", "IN"}, "ISB": {"Islamabad", "PK"},
	"IXC": {"Chandigarh", "IN"}, "JAI": {"Jaipur", "IN"}, "KHI": {"Karachi", "PK"},
	"KTM": {"Kathmandu", "NP"}, "LHE": {"Lahore", "PK"}, "MAA": {"Chennai", "IN"},
	"MLE": {"Malé", "MV"}, "NAG": {"Nagpur", "IN"}, "PAT": {"Patna", "IN"},
	"PNQ": {"Pune", "IN"}, "TAS": {"Tashkent", "UZ"}, "THR": {"Tehran", "IR"},
	"TRV": {"Thiruvananthapuram", "IN"},

	// Asia — West / Middle East
	"AMM": {"Amman", "JO"}, "AUH": {"Abu Dhabi", "AE"}, "BAH": {"Manama", "BH"},
	"BEY": {"Beirut", "LB"}, "BGW": {"Baghdad", "IQ"}, "DOH": {"Doha", "QA"},
	"DXB": {"Dubai", "AE"}, "EVN": {"Yerevan", "AM"}, "GYD": {"Baku", "AZ"},
	"JED": {"Jeddah", "SA"}, "KWI": {"Kuwait City", "KW"}, "MCT": {"Muscat", "OM"},
	"RUH": {"Riyadh", "SA"}, "TBS": {"Tbilisi", "GE"}, "TLV": {"Tel Aviv", "IL"},

	// Europe
	"AMS": {"Amsterdam", "NL"}, "ARN": {"Stockholm", "SE"}, "ATH": {"Athens", "GR"},
	"BCN": {"Barcelona", "ES"}, "BEG": {"Belgrade", "RS"}, "BRU": {"Brussels", "BE"},
	"BTS": {"Bratislava", "SK"}, "BUD": {"Budapest", "HU"}, "CDG": {"Paris", "FR"},
	"CPH": {"Copenhagen", "DK"}, "DME": {"Moscow", "RU"}, "DUB": {"Dublin", "IE"},
	"DUS": {"Düsseldorf", "DE"}, "EDI": {"Edinburgh", "GB"}, "FCO": {"Rome", "IT"},
	"FRA": {"Frankfurt", "DE"}, "GVA": {"Geneva", "CH"}, "HAM": {"Hamburg", "DE"},
	"HEL": {"Helsinki", "FI"}, "IST": {"Istanbul", "TR"}, "KBP": {"Kyiv", "UA"},
	"KEF": {"Reykjavík", "IS"}, "KIV": {"Chișinău", "MD"}, "KRK": {"Kraków", "PL"},
	"LCA": {"Larnaca", "CY"}, "LED": {"St. Petersburg", "RU"}, "LHR": {"London", "GB"},
	"LIS": {"Lisbon", "PT"}, "LJU": {"Ljubljana", "SI"}, "LUX": {"Luxembourg", "LU"},
	"LYS": {"Lyon", "FR"}, "MAD": {"Madrid", "ES"}, "MAN": {"Manchester", "GB"},
	"MRS": {"Marseille", "FR"}, "MUC": {"Munich", "DE"}, "MXP": {"Milan", "IT"},
	"OSL": {"Oslo", "NO"}, "OTP": {"Bucharest", "RO"}, "PMO": {"Palermo", "IT"},
	"PRG": {"Prague", "CZ"}, "RIX": {"Riga", "LV"}, "SOF": {"Sofia", "BG"},
	"SKP": {"Skopje", "MK"}, "SVO": {"Moscow", "RU"}, "SXF": {"Berlin", "DE"},
	"TIA": {"Tirana", "AL"}, "TLL": {"Tallinn", "EE"}, "TXL": {"Berlin", "DE"},
	"VIE": {"Vienna", "AT"}, "VNO": {"Vilnius", "LT"}, "WAW": {"Warsaw", "PL"},
	"ZAG": {"Zagreb", "HR"}, "ZRH": {"Zürich", "CH"},

	// Oceania
	"ADL": {"Adelaide", "AU"}, "AKL": {"Auckland", "NZ"}, "BNE": {"Brisbane", "AU"},
	"CBR": {"Canberra", "AU"}, "CHC": {"Christchurch", "NZ"}, "MEL": {"Melbourne", "AU"},
	"NOU": {"Nouméa", "NC"}, "PER": {"Perth", "AU"}, "PPT": {"Papeete", "PF"},
	"SYD": {"Sydney", "AU"}, "WLG": {"Wellington", "NZ"},
}

// coloLocation returns the human-readable city and ISO country code
// for a Cloudflare colo IATA suffix. Returns empty strings if unknown.
func coloLocation(code string) (city, country string) {
	if loc, ok := coloLocations[code]; ok {
		return loc.City, loc.Country
	}
	return "", ""
}
