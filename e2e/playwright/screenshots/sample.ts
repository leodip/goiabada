// The sample data the screenshots show: invented people at example.com, made on the command's new
// database through the admin console's forms, never written into it (#534).
//
// Each person's subject is a stand-in, fixed here. The auth server draws a random subject for every
// user it creates, the first administrator's included, so the users list differs on every new
// database; the capture writes these over the Subject cells of the users list just before it is
// captured, and alters no other text (decision 2).

export interface SampleUser {
  email: string;
  givenName: string;
  familyName: string;
  subject: string;
}

// The administrator the auth server seeds, which has no name and no username until the set-up
// session gives it them, with a Portuguese phone number for the Phone page.
export const administrator = {
  email: "admin@example.com",
  givenName: "Ada",
  familyName: "Administrator",
  username: "admin",
  subject: "2a06e6d0-e265-4d60-9209-bd46b91c655c",
  phoneCountry: "Portugal",
  phoneNumber: "912 345 678",
} as const;

// Enough people for the users list to draw its paginator: with the administrator, five pages of ten.
// The list is sorted by given name, so its first page shows the administrator and the nine given
// names that come first.
export const sampleUsers: readonly SampleUser[] = [
  { email: "aiko.tanaka@example.com", givenName: "Aiko", familyName: "Tanaka", subject: "c192ba3c-ab07-460b-b903-743e46996b16" },
  { email: "amara.okafor@example.com", givenName: "Amara", familyName: "Okafor", subject: "8439f12c-ec52-4aae-ae88-7aa90d731699" },
  { email: "arjun.mehta@example.com", givenName: "Arjun", familyName: "Mehta", subject: "dffaa94c-23eb-4817-adfb-b8daaaf6d40c" },
  { email: "beatriz.costa@example.com", givenName: "Beatriz", familyName: "Costa", subject: "155076b0-25f0-4380-b045-5c6d6bd2ba26" },
  { email: "bruno.almeida@example.com", givenName: "Bruno", familyName: "Almeida", subject: "7967abb7-bc2f-449a-b7af-b7f18960752e" },
  { email: "chen.wei@example.com", givenName: "Chen", familyName: "Wei", subject: "3b2a442a-682c-4b3d-bea4-89bd5bbab925" },
  { email: "clara.weiss@example.com", givenName: "Clara", familyName: "Weiss", subject: "bf0f2a85-8990-4ab3-8f1e-ea765a04c795" },
  { email: "diego.ramirez@example.com", givenName: "Diego", familyName: "Ramírez", subject: "ddff9069-bb63-4c34-9b2b-9b79bf196464" },
  { email: "elif.yilmaz@example.com", givenName: "Elif", familyName: "Yılmaz", subject: "3e16c955-922e-421f-b105-ae75335e6029" },
  { email: "emma.lindqvist@example.com", givenName: "Emma", familyName: "Lindqvist", subject: "746c5677-6696-4ec2-a027-751d7f3e2fc8" },
  { email: "fatima.haddad@example.com", givenName: "Fatima", familyName: "Haddad", subject: "6e29c3a8-4b2f-446a-a163-9e0a71343a74" },
  { email: "felix.brandt@example.com", givenName: "Felix", familyName: "Brandt", subject: "46e94083-9075-4aea-b537-9e9c75a16973" },
  { email: "grace.mensah@example.com", givenName: "Grace", familyName: "Mensah", subject: "b0b1b2ab-2158-41eb-9022-e6a0e4fd393d" },
  { email: "hana.novak@example.com", givenName: "Hana", familyName: "Novák", subject: "292c527f-d145-4513-ade0-a77906b989de" },
  { email: "hiroshi.sato@example.com", givenName: "Hiroshi", familyName: "Sato", subject: "080c140d-dc1d-4518-add7-eb2043e7a6de" },
  { email: "ines.moreau@example.com", givenName: "Inès", familyName: "Moreau", subject: "15962572-1916-4c0f-88b3-e0b517aa0105" },
  { email: "ivan.petrov@example.com", givenName: "Ivan", familyName: "Petrov", subject: "44aa653f-f8e5-4b4b-8652-941184a50093" },
  { email: "jonas.berg@example.com", givenName: "Jonas", familyName: "Berg", subject: "6e200341-e3b5-4461-9f9a-9129512fd805" },
  { email: "julia.kowalska@example.com", givenName: "Julia", familyName: "Kowalska", subject: "81e0c7c4-2716-40e8-b862-0985c21698d9" },
  { email: "kai.nakamura@example.com", givenName: "Kai", familyName: "Nakamura", subject: "65f55781-36b9-4658-af79-6dcea57b5076" },
  { email: "kofi.asante@example.com", givenName: "Kofi", familyName: "Asante", subject: "d840b27c-ff73-499b-aade-a261f8361b41" },
  { email: "laila.rahimi@example.com", givenName: "Laila", familyName: "Rahimi", subject: "293be8d3-58d2-4e3a-884e-e4fffd7e5555" },
  { email: "lucas.ferreira@example.com", givenName: "Lucas", familyName: "Ferreira", subject: "2750c19a-805c-4d50-b605-7c8db765cc44" },
  { email: "maya.cohen@example.com", givenName: "Maya", familyName: "Cohen", subject: "02f6dc02-7321-4965-9f6e-5c2ceaaf3ddf" },
  { email: "mateo.silva@example.com", givenName: "Mateo", familyName: "Silva", subject: "22fb3b2c-d802-46b1-a674-2360d26bf0b6" },
  { email: "nadia.popescu@example.com", givenName: "Nadia", familyName: "Popescu", subject: "ce5cc6ac-a86f-4707-ad00-1ac5de3c01d1" },
  { email: "noah.fischer@example.com", givenName: "Noah", familyName: "Fischer", subject: "d3229da7-5a29-42c6-994b-507621150cf0" },
  { email: "olga.ivanova@example.com", givenName: "Olga", familyName: "Ivanova", subject: "373b44c1-d24c-4c75-a0a9-9834a59c87b5" },
  { email: "omar.farouk@example.com", givenName: "Omar", familyName: "Farouk", subject: "088c91b4-cb50-4157-baad-392524ad5906" },
  { email: "priya.nair@example.com", givenName: "Priya", familyName: "Nair", subject: "e6f8939f-300c-44ab-835f-b8808a6b9e6f" },
  { email: "rafael.ortiz@example.com", givenName: "Rafael", familyName: "Ortiz", subject: "2b399665-ea4b-46bf-8fd1-7793b719c730" },
  { email: "rosa.delgado@example.com", givenName: "Rosa", familyName: "Delgado", subject: "a02c3877-c60a-4c91-9c4f-cdd83a6ae5d3" },
  { email: "samuel.adeyemi@example.com", givenName: "Samuel", familyName: "Adeyemi", subject: "1afb0034-2077-4a49-aa38-738b21b979a5" },
  { email: "sofia.rossi@example.com", givenName: "Sofia", familyName: "Rossi", subject: "08f8fec6-6a81-4a9b-bad3-7f181909d0f3" },
  { email: "tariq.hassan@example.com", givenName: "Tariq", familyName: "Hassan", subject: "bc08b1c4-79e1-46bd-816d-bd645dedb5d8" },
  { email: "thea.johansson@example.com", givenName: "Thea", familyName: "Johansson", subject: "0ef5f546-b3da-4912-9d20-330ae73b3f36" },
  { email: "uma.krishnan@example.com", givenName: "Uma", familyName: "Krishnan", subject: "52620c20-d0d5-458b-8540-8bd714610b11" },
  { email: "victor.dubois@example.com", givenName: "Victor", familyName: "Dubois", subject: "06121211-1ec7-4fb9-8297-fb40683abac9" },
  { email: "wanjiru.kamau@example.com", givenName: "Wanjiru", familyName: "Kamau", subject: "48b1883a-f3b8-420f-a704-974bb270ba78" },
  { email: "xavier.laurent@example.com", givenName: "Xavier", familyName: "Laurent", subject: "93d0a1d9-1f16-4b76-a3d7-baba0b4bfd95" },
  { email: "yara.nassar@example.com", givenName: "Yara", familyName: "Nassar", subject: "5b8fadbf-f807-465d-9f2f-c039f267ff48" },
  { email: "yusuf.demir@example.com", givenName: "Yusuf", familyName: "Demir", subject: "882ff41b-4074-4280-8693-9cba0ea77d16" },
  { email: "zainab.bello@example.com", givenName: "Zainab", familyName: "Bello", subject: "e6dc99ff-ea6b-44d2-b5ba-19b1ae49e024" },
  { email: "zoe.martin@example.com", givenName: "Zoe", familyName: "Martin", subject: "77d3b7c4-6509-4c1b-9350-2ce07e43d5f9" },
];
