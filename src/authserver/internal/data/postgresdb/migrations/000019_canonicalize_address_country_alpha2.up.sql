-- Migration 000019: canonicalize users.address_country to ISO 3166-1 alpha-2.
--
-- Background: the address country form previously posted alpha-3 codes
-- (e.g. 'USA') while the validator accepted a mix of alpha-2 / alpha-3 /
-- English names via biter777.ByName. The representation is now standardized
-- on alpha-2 so that localized country labels can be keyed off the
-- canonical code.
--
-- Step 1 converts known alpha-3 codes and canonical English country names
-- to alpha-2. Step 2 clears (sets to NULL) any remaining value that isn't
-- empty and isn't a recognized alpha-2 — typical case is foreign-language
-- aliases (e.g. 'AUSTRALIEN') or free-form text. Cleared rows surface as a
-- blank country dropdown on next edit, prompting the user to re-pick.

-- Step 1: convert known alpha-3 codes and canonical English names to alpha-2.
UPDATE users SET address_country = CASE address_country
    WHEN 'ABW' THEN 'AW'
    WHEN 'AFG' THEN 'AF'
    WHEN 'AGO' THEN 'AO'
    WHEN 'AIA' THEN 'AI'
    WHEN 'ALA' THEN 'AX'
    WHEN 'ALB' THEN 'AL'
    WHEN 'AND' THEN 'AD'
    WHEN 'ANT' THEN 'AN'
    WHEN 'ARE' THEN 'AE'
    WHEN 'ARG' THEN 'AR'
    WHEN 'ARM' THEN 'AM'
    WHEN 'ASM' THEN 'AS'
    WHEN 'ATA' THEN 'AQ'
    WHEN 'ATF' THEN 'TF'
    WHEN 'ATG' THEN 'AG'
    WHEN 'AUS' THEN 'AU'
    WHEN 'AUT' THEN 'AT'
    WHEN 'AZE' THEN 'AZ'
    WHEN 'Afghanistan' THEN 'AF'
    WHEN 'Aland Islands' THEN 'AX'
    WHEN 'Albania' THEN 'AL'
    WHEN 'Algeria' THEN 'DZ'
    WHEN 'American Samoa' THEN 'AS'
    WHEN 'Andorra' THEN 'AD'
    WHEN 'Angola' THEN 'AO'
    WHEN 'Anguilla' THEN 'AI'
    WHEN 'Antarctica' THEN 'AQ'
    WHEN 'Antigua and Barbuda' THEN 'AG'
    WHEN 'Argentina' THEN 'AR'
    WHEN 'Armenia' THEN 'AM'
    WHEN 'Aruba' THEN 'AW'
    WHEN 'Australia' THEN 'AU'
    WHEN 'Austria' THEN 'AT'
    WHEN 'Azerbaijan' THEN 'AZ'
    WHEN 'BDI' THEN 'BI'
    WHEN 'BEL' THEN 'BE'
    WHEN 'BEN' THEN 'BJ'
    WHEN 'BES' THEN 'BQ'
    WHEN 'BFA' THEN 'BF'
    WHEN 'BGD' THEN 'BD'
    WHEN 'BGR' THEN 'BG'
    WHEN 'BHR' THEN 'BH'
    WHEN 'BHS' THEN 'BS'
    WHEN 'BIH' THEN 'BA'
    WHEN 'BLM' THEN 'BL'
    WHEN 'BLR' THEN 'BY'
    WHEN 'BLZ' THEN 'BZ'
    WHEN 'BMU' THEN 'BM'
    WHEN 'BOL' THEN 'BO'
    WHEN 'BRA' THEN 'BR'
    WHEN 'BRB' THEN 'BB'
    WHEN 'BRN' THEN 'BN'
    WHEN 'BTN' THEN 'BT'
    WHEN 'BVT' THEN 'BV'
    WHEN 'BWA' THEN 'BW'
    WHEN 'Bahamas' THEN 'BS'
    WHEN 'Bahrain' THEN 'BH'
    WHEN 'Bangladesh' THEN 'BD'
    WHEN 'Barbados' THEN 'BB'
    WHEN 'Belarus' THEN 'BY'
    WHEN 'Belgium' THEN 'BE'
    WHEN 'Belize' THEN 'BZ'
    WHEN 'Benin' THEN 'BJ'
    WHEN 'Bermuda' THEN 'BM'
    WHEN 'Bhutan' THEN 'BT'
    WHEN 'Bolivia' THEN 'BO'
    WHEN 'Bonaire, Sint Eustatius And Saba' THEN 'BQ'
    WHEN 'Bosnia and Herzegovina' THEN 'BA'
    WHEN 'Botswana' THEN 'BW'
    WHEN 'Bouvet Island' THEN 'BV'
    WHEN 'Brazil' THEN 'BR'
    WHEN 'British Indian Ocean Territory' THEN 'IO'
    WHEN 'Brunei Darussalam' THEN 'BN'
    WHEN 'Bulgaria' THEN 'BG'
    WHEN 'Burkina Faso' THEN 'BF'
    WHEN 'Burundi' THEN 'BI'
    WHEN 'CAF' THEN 'CF'
    WHEN 'CAN' THEN 'CA'
    WHEN 'CCK' THEN 'CC'
    WHEN 'CHE' THEN 'CH'
    WHEN 'CHL' THEN 'CL'
    WHEN 'CHN' THEN 'CN'
    WHEN 'CIV' THEN 'CI'
    WHEN 'CMR' THEN 'CM'
    WHEN 'COD' THEN 'CD'
    WHEN 'COG' THEN 'CG'
    WHEN 'COK' THEN 'CK'
    WHEN 'COL' THEN 'CO'
    WHEN 'COM' THEN 'KM'
    WHEN 'CPV' THEN 'CV'
    WHEN 'CRI' THEN 'CR'
    WHEN 'CUB' THEN 'CU'
    WHEN 'CUW' THEN 'CW'
    WHEN 'CXR' THEN 'CX'
    WHEN 'CYM' THEN 'KY'
    WHEN 'CYP' THEN 'CY'
    WHEN 'CZE' THEN 'CZ'
    WHEN 'Cambodia' THEN 'KH'
    WHEN 'Cameroon' THEN 'CM'
    WHEN 'Canada' THEN 'CA'
    WHEN 'Cape Verde' THEN 'CV'
    WHEN 'Cayman Islands' THEN 'KY'
    WHEN 'Central African Republic' THEN 'CF'
    WHEN 'Chad' THEN 'TD'
    WHEN 'Chile' THEN 'CL'
    WHEN 'China' THEN 'CN'
    WHEN 'Christmas Island' THEN 'CX'
    WHEN 'Cocos (Keeling) Islands' THEN 'CC'
    WHEN 'Colombia' THEN 'CO'
    WHEN 'Comoros' THEN 'KM'
    WHEN 'Congo' THEN 'CG'
    WHEN 'Cook Islands' THEN 'CK'
    WHEN 'Costa Rica' THEN 'CR'
    WHEN 'Cote d''Ivoire' THEN 'CI'
    WHEN 'Croatia' THEN 'HR'
    WHEN 'Cuba' THEN 'CU'
    WHEN 'Curacao' THEN 'CW'
    WHEN 'Cyprus' THEN 'CY'
    WHEN 'Czechia' THEN 'CZ'
    WHEN 'DEU' THEN 'DE'
    WHEN 'DJI' THEN 'DJ'
    WHEN 'DMA' THEN 'DM'
    WHEN 'DNK' THEN 'DK'
    WHEN 'DOM' THEN 'DO'
    WHEN 'DZA' THEN 'DZ'
    WHEN 'Democratic People''s Republic of Korea' THEN 'KP'
    WHEN 'Democratic Republic of the Congo' THEN 'CD'
    WHEN 'Denmark' THEN 'DK'
    WHEN 'Djibouti' THEN 'DJ'
    WHEN 'Dominica' THEN 'DM'
    WHEN 'Dominican Republic' THEN 'DO'
    WHEN 'ECU' THEN 'EC'
    WHEN 'EGY' THEN 'EG'
    WHEN 'ERI' THEN 'ER'
    WHEN 'ESH' THEN 'EH'
    WHEN 'ESP' THEN 'ES'
    WHEN 'EST' THEN 'EE'
    WHEN 'ETH' THEN 'ET'
    WHEN 'Ecuador' THEN 'EC'
    WHEN 'Egypt' THEN 'EG'
    WHEN 'El Salvador' THEN 'SV'
    WHEN 'Equatorial Guinea' THEN 'GQ'
    WHEN 'Eritrea' THEN 'ER'
    WHEN 'Estonia' THEN 'EE'
    WHEN 'Ethiopia' THEN 'ET'
    WHEN 'FIN' THEN 'FI'
    WHEN 'FJI' THEN 'FJ'
    WHEN 'FLK' THEN 'FK'
    WHEN 'FRA' THEN 'FR'
    WHEN 'FRO' THEN 'FO'
    WHEN 'FSM' THEN 'FM'
    WHEN 'Falkland Islands (Malvinas)' THEN 'FK'
    WHEN 'Faroe Islands' THEN 'FO'
    WHEN 'Fiji' THEN 'FJ'
    WHEN 'Finland' THEN 'FI'
    WHEN 'France' THEN 'FR'
    WHEN 'French Guiana' THEN 'GF'
    WHEN 'French Polynesia' THEN 'PF'
    WHEN 'French Southern Territories' THEN 'TF'
    WHEN 'GAB' THEN 'GA'
    WHEN 'GBR' THEN 'GB'
    WHEN 'GEO' THEN 'GE'
    WHEN 'GGY' THEN 'GG'
    WHEN 'GHA' THEN 'GH'
    WHEN 'GIB' THEN 'GI'
    WHEN 'GIN' THEN 'GN'
    WHEN 'GLP' THEN 'GP'
    WHEN 'GMB' THEN 'GM'
    WHEN 'GNB' THEN 'GW'
    WHEN 'GNQ' THEN 'GQ'
    WHEN 'GRC' THEN 'GR'
    WHEN 'GRD' THEN 'GD'
    WHEN 'GRL' THEN 'GL'
    WHEN 'GTM' THEN 'GT'
    WHEN 'GUF' THEN 'GF'
    WHEN 'GUM' THEN 'GU'
    WHEN 'GUY' THEN 'GY'
    WHEN 'Gabon' THEN 'GA'
    WHEN 'Gambia' THEN 'GM'
    WHEN 'Georgia' THEN 'GE'
    WHEN 'Germany' THEN 'DE'
    WHEN 'Ghana' THEN 'GH'
    WHEN 'Gibraltar' THEN 'GI'
    WHEN 'Greece' THEN 'GR'
    WHEN 'Greenland' THEN 'GL'
    WHEN 'Grenada' THEN 'GD'
    WHEN 'Guadeloupe' THEN 'GP'
    WHEN 'Guam' THEN 'GU'
    WHEN 'Guatemala' THEN 'GT'
    WHEN 'Guernsey' THEN 'GG'
    WHEN 'Guinea' THEN 'GN'
    WHEN 'Guinea-Bissau' THEN 'GW'
    WHEN 'Guyana' THEN 'GY'
    WHEN 'HKG' THEN 'HK'
    WHEN 'HMD' THEN 'HM'
    WHEN 'HND' THEN 'HN'
    WHEN 'HRV' THEN 'HR'
    WHEN 'HTI' THEN 'HT'
    WHEN 'HUN' THEN 'HU'
    WHEN 'Haiti' THEN 'HT'
    WHEN 'Heard Island and McDonald Islands' THEN 'HM'
    WHEN 'Holy See (Vatican City State)' THEN 'VA'
    WHEN 'Honduras' THEN 'HN'
    WHEN 'Hong Kong (Special Administrative Region of China)' THEN 'HK'
    WHEN 'Hungary' THEN 'HU'
    WHEN 'IDN' THEN 'ID'
    WHEN 'IMN' THEN 'IM'
    WHEN 'IND' THEN 'IN'
    WHEN 'IOT' THEN 'IO'
    WHEN 'IRL' THEN 'IE'
    WHEN 'IRN' THEN 'IR'
    WHEN 'IRQ' THEN 'IQ'
    WHEN 'ISL' THEN 'IS'
    WHEN 'ISR' THEN 'IL'
    WHEN 'ITA' THEN 'IT'
    WHEN 'Iceland' THEN 'IS'
    WHEN 'India' THEN 'IN'
    WHEN 'Indonesia' THEN 'ID'
    WHEN 'Iran (Islamic Republic of)' THEN 'IR'
    WHEN 'Iraq' THEN 'IQ'
    WHEN 'Ireland' THEN 'IE'
    WHEN 'Isle Of Man' THEN 'IM'
    WHEN 'Israel' THEN 'IL'
    WHEN 'Italy' THEN 'IT'
    WHEN 'JAM' THEN 'JM'
    WHEN 'JEY' THEN 'JE'
    WHEN 'JOR' THEN 'JO'
    WHEN 'JPN' THEN 'JP'
    WHEN 'Jamaica' THEN 'JM'
    WHEN 'Japan' THEN 'JP'
    WHEN 'Jersey' THEN 'JE'
    WHEN 'Jordan' THEN 'JO'
    WHEN 'KAZ' THEN 'KZ'
    WHEN 'KEN' THEN 'KE'
    WHEN 'KGZ' THEN 'KG'
    WHEN 'KHM' THEN 'KH'
    WHEN 'KIR' THEN 'KI'
    WHEN 'KNA' THEN 'KN'
    WHEN 'KOR' THEN 'KR'
    WHEN 'KWT' THEN 'KW'
    WHEN 'Kazakhstan' THEN 'KZ'
    WHEN 'Kenya' THEN 'KE'
    WHEN 'Kiribati' THEN 'KI'
    WHEN 'Kosovo' THEN 'XK'
    WHEN 'Kuwait' THEN 'KW'
    WHEN 'Kyrgyzstan' THEN 'KG'
    WHEN 'LAO' THEN 'LA'
    WHEN 'LBN' THEN 'LB'
    WHEN 'LBR' THEN 'LR'
    WHEN 'LBY' THEN 'LY'
    WHEN 'LCA' THEN 'LC'
    WHEN 'LIE' THEN 'LI'
    WHEN 'LKA' THEN 'LK'
    WHEN 'LSO' THEN 'LS'
    WHEN 'LTU' THEN 'LT'
    WHEN 'LUX' THEN 'LU'
    WHEN 'LVA' THEN 'LV'
    WHEN 'Lao People''s Democratic Republic' THEN 'LA'
    WHEN 'Latvia' THEN 'LV'
    WHEN 'Lebanon' THEN 'LB'
    WHEN 'Lesotho' THEN 'LS'
    WHEN 'Liberia' THEN 'LR'
    WHEN 'Libyan Arab Jamahiriya' THEN 'LY'
    WHEN 'Liechtenstein' THEN 'LI'
    WHEN 'Lithuania' THEN 'LT'
    WHEN 'Luxembourg' THEN 'LU'
    WHEN 'MAC' THEN 'MO'
    WHEN 'MAF' THEN 'MF'
    WHEN 'MAR' THEN 'MA'
    WHEN 'MCO' THEN 'MC'
    WHEN 'MDA' THEN 'MD'
    WHEN 'MDG' THEN 'MG'
    WHEN 'MDV' THEN 'MV'
    WHEN 'MEX' THEN 'MX'
    WHEN 'MHL' THEN 'MH'
    WHEN 'MKD' THEN 'MK'
    WHEN 'MLI' THEN 'ML'
    WHEN 'MLT' THEN 'MT'
    WHEN 'MMR' THEN 'MM'
    WHEN 'MNE' THEN 'ME'
    WHEN 'MNG' THEN 'MN'
    WHEN 'MNP' THEN 'MP'
    WHEN 'MOZ' THEN 'MZ'
    WHEN 'MRT' THEN 'MR'
    WHEN 'MSR' THEN 'MS'
    WHEN 'MTQ' THEN 'MQ'
    WHEN 'MUS' THEN 'MU'
    WHEN 'MWI' THEN 'MW'
    WHEN 'MYS' THEN 'MY'
    WHEN 'MYT' THEN 'YT'
    WHEN 'Macau (Special Administrative Region of China)' THEN 'MO'
    WHEN 'Madagascar' THEN 'MG'
    WHEN 'Malawi' THEN 'MW'
    WHEN 'Malaysia' THEN 'MY'
    WHEN 'Maldives' THEN 'MV'
    WHEN 'Mali' THEN 'ML'
    WHEN 'Malta' THEN 'MT'
    WHEN 'Marshall Islands' THEN 'MH'
    WHEN 'Martinique' THEN 'MQ'
    WHEN 'Mauritania' THEN 'MR'
    WHEN 'Mauritius' THEN 'MU'
    WHEN 'Mayotte' THEN 'YT'
    WHEN 'Mexico' THEN 'MX'
    WHEN 'Micronesia (Federated States of)' THEN 'FM'
    WHEN 'Moldova (Republic of)' THEN 'MD'
    WHEN 'Monaco' THEN 'MC'
    WHEN 'Mongolia' THEN 'MN'
    WHEN 'Montenegro' THEN 'ME'
    WHEN 'Montserrat' THEN 'MS'
    WHEN 'Morocco' THEN 'MA'
    WHEN 'Mozambique' THEN 'MZ'
    WHEN 'Myanmar' THEN 'MM'
    WHEN 'NAM' THEN 'NA'
    WHEN 'NCL' THEN 'NC'
    WHEN 'NER' THEN 'NE'
    WHEN 'NFK' THEN 'NF'
    WHEN 'NGA' THEN 'NG'
    WHEN 'NIC' THEN 'NI'
    WHEN 'NIU' THEN 'NU'
    WHEN 'NLD' THEN 'NL'
    WHEN 'NOR' THEN 'NO'
    WHEN 'NPL' THEN 'NP'
    WHEN 'NRU' THEN 'NR'
    WHEN 'NZL' THEN 'NZ'
    WHEN 'Namibia' THEN 'NA'
    WHEN 'Nauru' THEN 'NR'
    WHEN 'Nepal' THEN 'NP'
    WHEN 'Netherlands' THEN 'NL'
    WHEN 'Netherlands Antilles' THEN 'AN'
    WHEN 'New Caledonia' THEN 'NC'
    WHEN 'New Zealand' THEN 'NZ'
    WHEN 'Nicaragua' THEN 'NI'
    WHEN 'Niger' THEN 'NE'
    WHEN 'Nigeria' THEN 'NG'
    WHEN 'Niue' THEN 'NU'
    WHEN 'Norfolk Island' THEN 'NF'
    WHEN 'North Macedonia (Republic of North Macedonia)' THEN 'MK'
    WHEN 'Northern Mariana Islands' THEN 'MP'
    WHEN 'Norway' THEN 'NO'
    WHEN 'OMN' THEN 'OM'
    WHEN 'Oman' THEN 'OM'
    WHEN 'PAK' THEN 'PK'
    WHEN 'PAN' THEN 'PA'
    WHEN 'PCN' THEN 'PN'
    WHEN 'PER' THEN 'PE'
    WHEN 'PHL' THEN 'PH'
    WHEN 'PLW' THEN 'PW'
    WHEN 'PNG' THEN 'PG'
    WHEN 'POL' THEN 'PL'
    WHEN 'PRI' THEN 'PR'
    WHEN 'PRK' THEN 'KP'
    WHEN 'PRT' THEN 'PT'
    WHEN 'PRY' THEN 'PY'
    WHEN 'PSE' THEN 'PS'
    WHEN 'PYF' THEN 'PF'
    WHEN 'Pakistan' THEN 'PK'
    WHEN 'Palau' THEN 'PW'
    WHEN 'Palestinian Territory (Occupied)' THEN 'PS'
    WHEN 'Panama' THEN 'PA'
    WHEN 'Papua New Guinea' THEN 'PG'
    WHEN 'Paraguay' THEN 'PY'
    WHEN 'Peru' THEN 'PE'
    WHEN 'Philippines' THEN 'PH'
    WHEN 'Pitcairn' THEN 'PN'
    WHEN 'Poland' THEN 'PL'
    WHEN 'Portugal' THEN 'PT'
    WHEN 'Puerto Rico' THEN 'PR'
    WHEN 'QAT' THEN 'QA'
    WHEN 'Qatar' THEN 'QA'
    WHEN 'REU' THEN 'RE'
    WHEN 'ROU' THEN 'RO'
    WHEN 'RUS' THEN 'RU'
    WHEN 'RWA' THEN 'RW'
    WHEN 'Republic of Korea' THEN 'KR'
    WHEN 'Reunion' THEN 'RE'
    WHEN 'Romania' THEN 'RO'
    WHEN 'Russian Federation' THEN 'RU'
    WHEN 'Rwanda' THEN 'RW'
    WHEN 'SAU' THEN 'SA'
    WHEN 'SDN' THEN 'SD'
    WHEN 'SEN' THEN 'SN'
    WHEN 'SGP' THEN 'SG'
    WHEN 'SGS' THEN 'GS'
    WHEN 'SHN' THEN 'SH'
    WHEN 'SJM' THEN 'SJ'
    WHEN 'SLB' THEN 'SB'
    WHEN 'SLE' THEN 'SL'
    WHEN 'SLV' THEN 'SV'
    WHEN 'SMR' THEN 'SM'
    WHEN 'SOM' THEN 'SO'
    WHEN 'SPM' THEN 'PM'
    WHEN 'SRB' THEN 'RS'
    WHEN 'SSD' THEN 'SS'
    WHEN 'STP' THEN 'ST'
    WHEN 'SUR' THEN 'SR'
    WHEN 'SVK' THEN 'SK'
    WHEN 'SVN' THEN 'SI'
    WHEN 'SWE' THEN 'SE'
    WHEN 'SWZ' THEN 'SZ'
    WHEN 'SXM' THEN 'SX'
    WHEN 'SYC' THEN 'SC'
    WHEN 'SYR' THEN 'SY'
    WHEN 'Saint Barthelemy' THEN 'BL'
    WHEN 'Saint Helena' THEN 'SH'
    WHEN 'Saint Kitts and Nevis' THEN 'KN'
    WHEN 'Saint Lucia' THEN 'LC'
    WHEN 'Saint Martin French' THEN 'MF'
    WHEN 'Saint Pierre and Miquelon' THEN 'PM'
    WHEN 'Saint Vincent and the Grenadines' THEN 'VC'
    WHEN 'Samoa' THEN 'WS'
    WHEN 'San Marino' THEN 'SM'
    WHEN 'Sao Tome and Principe' THEN 'ST'
    WHEN 'Saudi Arabia' THEN 'SA'
    WHEN 'Senegal' THEN 'SN'
    WHEN 'Serbia' THEN 'RS'
    WHEN 'Seychelles' THEN 'SC'
    WHEN 'Sierra Leone' THEN 'SL'
    WHEN 'Singapore' THEN 'SG'
    WHEN 'Sint Maarten Dutch' THEN 'SX'
    WHEN 'Slovakia' THEN 'SK'
    WHEN 'Slovenia' THEN 'SI'
    WHEN 'Solomon Islands' THEN 'SB'
    WHEN 'Somalia' THEN 'SO'
    WHEN 'South Africa' THEN 'ZA'
    WHEN 'South Georgia and The South Sandwich Islands' THEN 'GS'
    WHEN 'South Sudan' THEN 'SS'
    WHEN 'Spain' THEN 'ES'
    WHEN 'Sri Lanka' THEN 'LK'
    WHEN 'Sudan' THEN 'SD'
    WHEN 'Suriname' THEN 'SR'
    WHEN 'Svalbard and Jan Mayen Islands' THEN 'SJ'
    WHEN 'Swaziland' THEN 'SZ'
    WHEN 'Sweden' THEN 'SE'
    WHEN 'Switzerland' THEN 'CH'
    WHEN 'Syrian Arab Republic' THEN 'SY'
    WHEN 'TCA' THEN 'TC'
    WHEN 'TCD' THEN 'TD'
    WHEN 'TGO' THEN 'TG'
    WHEN 'THA' THEN 'TH'
    WHEN 'TJK' THEN 'TJ'
    WHEN 'TKL' THEN 'TK'
    WHEN 'TKM' THEN 'TM'
    WHEN 'TLS' THEN 'TL'
    WHEN 'TON' THEN 'TO'
    WHEN 'TTO' THEN 'TT'
    WHEN 'TUN' THEN 'TN'
    WHEN 'TUR' THEN 'TR'
    WHEN 'TUV' THEN 'TV'
    WHEN 'TWN' THEN 'TW'
    WHEN 'TZA' THEN 'TZ'
    WHEN 'Taiwan (Province of China)' THEN 'TW'
    WHEN 'Tajikistan' THEN 'TJ'
    WHEN 'Tanzania (United Republic of)' THEN 'TZ'
    WHEN 'Thailand' THEN 'TH'
    WHEN 'Timor-Leste (East Timor)' THEN 'TL'
    WHEN 'Togo' THEN 'TG'
    WHEN 'Tokelau' THEN 'TK'
    WHEN 'Tonga' THEN 'TO'
    WHEN 'Trinidad and Tobago' THEN 'TT'
    WHEN 'Tunisia' THEN 'TN'
    WHEN 'Turkey' THEN 'TR'
    WHEN 'Turkmenistan' THEN 'TM'
    WHEN 'Turks and Caicos Islands' THEN 'TC'
    WHEN 'Tuvalu' THEN 'TV'
    WHEN 'UGA' THEN 'UG'
    WHEN 'UKR' THEN 'UA'
    WHEN 'UMI' THEN 'UM'
    WHEN 'URY' THEN 'UY'
    WHEN 'USA' THEN 'US'
    WHEN 'UZB' THEN 'UZ'
    WHEN 'Uganda' THEN 'UG'
    WHEN 'Ukraine' THEN 'UA'
    WHEN 'United Arab Emirates' THEN 'AE'
    WHEN 'United Kingdom' THEN 'GB'
    WHEN 'United States' THEN 'US'
    WHEN 'United States Minor Outlying Islands' THEN 'UM'
    WHEN 'Uruguay' THEN 'UY'
    WHEN 'Uzbekistan' THEN 'UZ'
    WHEN 'VAT' THEN 'VA'
    WHEN 'VCT' THEN 'VC'
    WHEN 'VEN' THEN 'VE'
    WHEN 'VGB' THEN 'VG'
    WHEN 'VIR' THEN 'VI'
    WHEN 'VNM' THEN 'VN'
    WHEN 'VUT' THEN 'VU'
    WHEN 'Vanuatu' THEN 'VU'
    WHEN 'Venezuela' THEN 'VE'
    WHEN 'Vietnam' THEN 'VN'
    WHEN 'Virgin Islands British' THEN 'VG'
    WHEN 'Virgin Islands US' THEN 'VI'
    WHEN 'WLF' THEN 'WF'
    WHEN 'WSM' THEN 'WS'
    WHEN 'Wallis and Futuna Islands' THEN 'WF'
    WHEN 'Western Sahara' THEN 'EH'
    WHEN 'XKX' THEN 'XK'
    WHEN 'YEM' THEN 'YE'
    WHEN 'YUG' THEN 'YU'
    WHEN 'Yemen' THEN 'YE'
    WHEN 'Yugoslavia' THEN 'YU'
    WHEN 'ZAF' THEN 'ZA'
    WHEN 'ZMB' THEN 'ZM'
    WHEN 'ZWE' THEN 'ZW'
    WHEN 'Zambia' THEN 'ZM'
    WHEN 'Zimbabwe' THEN 'ZW'
    ELSE address_country
END
WHERE address_country IN (
    'ABW',
    'AFG',
    'AGO',
    'AIA',
    'ALA',
    'ALB',
    'AND',
    'ANT',
    'ARE',
    'ARG',
    'ARM',
    'ASM',
    'ATA',
    'ATF',
    'ATG',
    'AUS',
    'AUT',
    'AZE',
    'Afghanistan',
    'Aland Islands',
    'Albania',
    'Algeria',
    'American Samoa',
    'Andorra',
    'Angola',
    'Anguilla',
    'Antarctica',
    'Antigua and Barbuda',
    'Argentina',
    'Armenia',
    'Aruba',
    'Australia',
    'Austria',
    'Azerbaijan',
    'BDI',
    'BEL',
    'BEN',
    'BES',
    'BFA',
    'BGD',
    'BGR',
    'BHR',
    'BHS',
    'BIH',
    'BLM',
    'BLR',
    'BLZ',
    'BMU',
    'BOL',
    'BRA',
    'BRB',
    'BRN',
    'BTN',
    'BVT',
    'BWA',
    'Bahamas',
    'Bahrain',
    'Bangladesh',
    'Barbados',
    'Belarus',
    'Belgium',
    'Belize',
    'Benin',
    'Bermuda',
    'Bhutan',
    'Bolivia',
    'Bonaire, Sint Eustatius And Saba',
    'Bosnia and Herzegovina',
    'Botswana',
    'Bouvet Island',
    'Brazil',
    'British Indian Ocean Territory',
    'Brunei Darussalam',
    'Bulgaria',
    'Burkina Faso',
    'Burundi',
    'CAF',
    'CAN',
    'CCK',
    'CHE',
    'CHL',
    'CHN',
    'CIV',
    'CMR',
    'COD',
    'COG',
    'COK',
    'COL',
    'COM',
    'CPV',
    'CRI',
    'CUB',
    'CUW',
    'CXR',
    'CYM',
    'CYP',
    'CZE',
    'Cambodia',
    'Cameroon',
    'Canada',
    'Cape Verde',
    'Cayman Islands',
    'Central African Republic',
    'Chad',
    'Chile',
    'China',
    'Christmas Island',
    'Cocos (Keeling) Islands',
    'Colombia',
    'Comoros',
    'Congo',
    'Cook Islands',
    'Costa Rica',
    'Cote d''Ivoire',
    'Croatia',
    'Cuba',
    'Curacao',
    'Cyprus',
    'Czechia',
    'DEU',
    'DJI',
    'DMA',
    'DNK',
    'DOM',
    'DZA',
    'Democratic People''s Republic of Korea',
    'Democratic Republic of the Congo',
    'Denmark',
    'Djibouti',
    'Dominica',
    'Dominican Republic',
    'ECU',
    'EGY',
    'ERI',
    'ESH',
    'ESP',
    'EST',
    'ETH',
    'Ecuador',
    'Egypt',
    'El Salvador',
    'Equatorial Guinea',
    'Eritrea',
    'Estonia',
    'Ethiopia',
    'FIN',
    'FJI',
    'FLK',
    'FRA',
    'FRO',
    'FSM',
    'Falkland Islands (Malvinas)',
    'Faroe Islands',
    'Fiji',
    'Finland',
    'France',
    'French Guiana',
    'French Polynesia',
    'French Southern Territories',
    'GAB',
    'GBR',
    'GEO',
    'GGY',
    'GHA',
    'GIB',
    'GIN',
    'GLP',
    'GMB',
    'GNB',
    'GNQ',
    'GRC',
    'GRD',
    'GRL',
    'GTM',
    'GUF',
    'GUM',
    'GUY',
    'Gabon',
    'Gambia',
    'Georgia',
    'Germany',
    'Ghana',
    'Gibraltar',
    'Greece',
    'Greenland',
    'Grenada',
    'Guadeloupe',
    'Guam',
    'Guatemala',
    'Guernsey',
    'Guinea',
    'Guinea-Bissau',
    'Guyana',
    'HKG',
    'HMD',
    'HND',
    'HRV',
    'HTI',
    'HUN',
    'Haiti',
    'Heard Island and McDonald Islands',
    'Holy See (Vatican City State)',
    'Honduras',
    'Hong Kong (Special Administrative Region of China)',
    'Hungary',
    'IDN',
    'IMN',
    'IND',
    'IOT',
    'IRL',
    'IRN',
    'IRQ',
    'ISL',
    'ISR',
    'ITA',
    'Iceland',
    'India',
    'Indonesia',
    'Iran (Islamic Republic of)',
    'Iraq',
    'Ireland',
    'Isle Of Man',
    'Israel',
    'Italy',
    'JAM',
    'JEY',
    'JOR',
    'JPN',
    'Jamaica',
    'Japan',
    'Jersey',
    'Jordan',
    'KAZ',
    'KEN',
    'KGZ',
    'KHM',
    'KIR',
    'KNA',
    'KOR',
    'KWT',
    'Kazakhstan',
    'Kenya',
    'Kiribati',
    'Kosovo',
    'Kuwait',
    'Kyrgyzstan',
    'LAO',
    'LBN',
    'LBR',
    'LBY',
    'LCA',
    'LIE',
    'LKA',
    'LSO',
    'LTU',
    'LUX',
    'LVA',
    'Lao People''s Democratic Republic',
    'Latvia',
    'Lebanon',
    'Lesotho',
    'Liberia',
    'Libyan Arab Jamahiriya',
    'Liechtenstein',
    'Lithuania',
    'Luxembourg',
    'MAC',
    'MAF',
    'MAR',
    'MCO',
    'MDA',
    'MDG',
    'MDV',
    'MEX',
    'MHL',
    'MKD',
    'MLI',
    'MLT',
    'MMR',
    'MNE',
    'MNG',
    'MNP',
    'MOZ',
    'MRT',
    'MSR',
    'MTQ',
    'MUS',
    'MWI',
    'MYS',
    'MYT',
    'Macau (Special Administrative Region of China)',
    'Madagascar',
    'Malawi',
    'Malaysia',
    'Maldives',
    'Mali',
    'Malta',
    'Marshall Islands',
    'Martinique',
    'Mauritania',
    'Mauritius',
    'Mayotte',
    'Mexico',
    'Micronesia (Federated States of)',
    'Moldova (Republic of)',
    'Monaco',
    'Mongolia',
    'Montenegro',
    'Montserrat',
    'Morocco',
    'Mozambique',
    'Myanmar',
    'NAM',
    'NCL',
    'NER',
    'NFK',
    'NGA',
    'NIC',
    'NIU',
    'NLD',
    'NOR',
    'NPL',
    'NRU',
    'NZL',
    'Namibia',
    'Nauru',
    'Nepal',
    'Netherlands',
    'Netherlands Antilles',
    'New Caledonia',
    'New Zealand',
    'Nicaragua',
    'Niger',
    'Nigeria',
    'Niue',
    'Norfolk Island',
    'North Macedonia (Republic of North Macedonia)',
    'Northern Mariana Islands',
    'Norway',
    'OMN',
    'Oman',
    'PAK',
    'PAN',
    'PCN',
    'PER',
    'PHL',
    'PLW',
    'PNG',
    'POL',
    'PRI',
    'PRK',
    'PRT',
    'PRY',
    'PSE',
    'PYF',
    'Pakistan',
    'Palau',
    'Palestinian Territory (Occupied)',
    'Panama',
    'Papua New Guinea',
    'Paraguay',
    'Peru',
    'Philippines',
    'Pitcairn',
    'Poland',
    'Portugal',
    'Puerto Rico',
    'QAT',
    'Qatar',
    'REU',
    'ROU',
    'RUS',
    'RWA',
    'Republic of Korea',
    'Reunion',
    'Romania',
    'Russian Federation',
    'Rwanda',
    'SAU',
    'SDN',
    'SEN',
    'SGP',
    'SGS',
    'SHN',
    'SJM',
    'SLB',
    'SLE',
    'SLV',
    'SMR',
    'SOM',
    'SPM',
    'SRB',
    'SSD',
    'STP',
    'SUR',
    'SVK',
    'SVN',
    'SWE',
    'SWZ',
    'SXM',
    'SYC',
    'SYR',
    'Saint Barthelemy',
    'Saint Helena',
    'Saint Kitts and Nevis',
    'Saint Lucia',
    'Saint Martin French',
    'Saint Pierre and Miquelon',
    'Saint Vincent and the Grenadines',
    'Samoa',
    'San Marino',
    'Sao Tome and Principe',
    'Saudi Arabia',
    'Senegal',
    'Serbia',
    'Seychelles',
    'Sierra Leone',
    'Singapore',
    'Sint Maarten Dutch',
    'Slovakia',
    'Slovenia',
    'Solomon Islands',
    'Somalia',
    'South Africa',
    'South Georgia and The South Sandwich Islands',
    'South Sudan',
    'Spain',
    'Sri Lanka',
    'Sudan',
    'Suriname',
    'Svalbard and Jan Mayen Islands',
    'Swaziland',
    'Sweden',
    'Switzerland',
    'Syrian Arab Republic',
    'TCA',
    'TCD',
    'TGO',
    'THA',
    'TJK',
    'TKL',
    'TKM',
    'TLS',
    'TON',
    'TTO',
    'TUN',
    'TUR',
    'TUV',
    'TWN',
    'TZA',
    'Taiwan (Province of China)',
    'Tajikistan',
    'Tanzania (United Republic of)',
    'Thailand',
    'Timor-Leste (East Timor)',
    'Togo',
    'Tokelau',
    'Tonga',
    'Trinidad and Tobago',
    'Tunisia',
    'Turkey',
    'Turkmenistan',
    'Turks and Caicos Islands',
    'Tuvalu',
    'UGA',
    'UKR',
    'UMI',
    'URY',
    'USA',
    'UZB',
    'Uganda',
    'Ukraine',
    'United Arab Emirates',
    'United Kingdom',
    'United States',
    'United States Minor Outlying Islands',
    'Uruguay',
    'Uzbekistan',
    'VAT',
    'VCT',
    'VEN',
    'VGB',
    'VIR',
    'VNM',
    'VUT',
    'Vanuatu',
    'Venezuela',
    'Vietnam',
    'Virgin Islands British',
    'Virgin Islands US',
    'WLF',
    'WSM',
    'Wallis and Futuna Islands',
    'Western Sahara',
    'XKX',
    'YEM',
    'YUG',
    'Yemen',
    'Yugoslavia',
    'ZAF',
    'ZMB',
    'ZWE',
    'Zambia',
    'Zimbabwe'
);

-- Step 2: clear values that are neither empty nor a recognized alpha-2 code.
UPDATE users SET address_country = NULL
WHERE address_country IS NOT NULL
  AND address_country != ''
  AND address_country NOT IN (
    'AD',
    'AE',
    'AF',
    'AG',
    'AI',
    'AL',
    'AM',
    'AN',
    'AO',
    'AQ',
    'AR',
    'AS',
    'AT',
    'AU',
    'AW',
    'AX',
    'AZ',
    'BA',
    'BB',
    'BD',
    'BE',
    'BF',
    'BG',
    'BH',
    'BI',
    'BJ',
    'BL',
    'BM',
    'BN',
    'BO',
    'BQ',
    'BR',
    'BS',
    'BT',
    'BV',
    'BW',
    'BY',
    'BZ',
    'CA',
    'CC',
    'CD',
    'CF',
    'CG',
    'CH',
    'CI',
    'CK',
    'CL',
    'CM',
    'CN',
    'CO',
    'CR',
    'CU',
    'CV',
    'CW',
    'CX',
    'CY',
    'CZ',
    'DE',
    'DJ',
    'DK',
    'DM',
    'DO',
    'DZ',
    'EC',
    'EE',
    'EG',
    'EH',
    'ER',
    'ES',
    'ET',
    'FI',
    'FJ',
    'FK',
    'FM',
    'FO',
    'FR',
    'GA',
    'GB',
    'GD',
    'GE',
    'GF',
    'GG',
    'GH',
    'GI',
    'GL',
    'GM',
    'GN',
    'GP',
    'GQ',
    'GR',
    'GS',
    'GT',
    'GU',
    'GW',
    'GY',
    'HK',
    'HM',
    'HN',
    'HR',
    'HT',
    'HU',
    'ID',
    'IE',
    'IL',
    'IM',
    'IN',
    'IO',
    'IQ',
    'IR',
    'IS',
    'IT',
    'JE',
    'JM',
    'JO',
    'JP',
    'KE',
    'KG',
    'KH',
    'KI',
    'KM',
    'KN',
    'KP',
    'KR',
    'KW',
    'KY',
    'KZ',
    'LA',
    'LB',
    'LC',
    'LI',
    'LK',
    'LR',
    'LS',
    'LT',
    'LU',
    'LV',
    'LY',
    'MA',
    'MC',
    'MD',
    'ME',
    'MF',
    'MG',
    'MH',
    'MK',
    'ML',
    'MM',
    'MN',
    'MO',
    'MP',
    'MQ',
    'MR',
    'MS',
    'MT',
    'MU',
    'MV',
    'MW',
    'MX',
    'MY',
    'MZ',
    'NA',
    'NC',
    'NE',
    'NF',
    'NG',
    'NI',
    'NL',
    'NO',
    'NP',
    'NR',
    'NU',
    'NZ',
    'OM',
    'PA',
    'PE',
    'PF',
    'PG',
    'PH',
    'PK',
    'PL',
    'PM',
    'PN',
    'PR',
    'PS',
    'PT',
    'PW',
    'PY',
    'QA',
    'RE',
    'RO',
    'RS',
    'RU',
    'RW',
    'SA',
    'SB',
    'SC',
    'SD',
    'SE',
    'SG',
    'SH',
    'SI',
    'SJ',
    'SK',
    'SL',
    'SM',
    'SN',
    'SO',
    'SR',
    'SS',
    'ST',
    'SV',
    'SX',
    'SY',
    'SZ',
    'TC',
    'TD',
    'TF',
    'TG',
    'TH',
    'TJ',
    'TK',
    'TL',
    'TM',
    'TN',
    'TO',
    'TR',
    'TT',
    'TV',
    'TW',
    'TZ',
    'UA',
    'UG',
    'UM',
    'US',
    'UY',
    'UZ',
    'VA',
    'VC',
    'VE',
    'VG',
    'VI',
    'VN',
    'VU',
    'WF',
    'WS',
    'XK',
    'YE',
    'YT',
    'YU',
    'ZA',
    'ZM',
    'ZW'
  );
