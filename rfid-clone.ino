// PINS: RST > 9, MISO > 12, MOSI > 11, SCK > 13, SDK > 10
// 3.3v - 9 - GND - N/A - 12 - 11 - 13 - 10

#include <SPI.h>      //include the SPI library
#include <MFRC522.h>  //include the MFRC522 RFID reader library
#define RST_PIN 9     //reset pin, which can be changed to another digital pin if needed.
#define SS_PIN 10     //SS or the slave select pin, which can be changed to another digital pin if needed.

MFRC522 mfrc522(SS_PIN, RST_PIN);  // create a MFRC522 instant.
MFRC522::MIFARE_Key key;           //create a MIFARE_Key struct named 'key' to hold the card information

byte uidData[4];// = { 0x34, 0x78, 0xCE, 0xE1 };
byte data[64][18];
bool writeMode = false;

void setup() {
  Serial.begin(115200);  // Initialize serial communications with the PC
  pinMode(13, OUTPUT);
  SPI.begin();         // Init SPI bus
  mfrc522.PCD_Init();  // Init MFRC522 card
  Serial.println("\t*** READ MODE ***");
  Serial.println("Scan a MIFARE Classic card to save UID and data");
  for (byte i = 0; i < 6; i++) {
    key.keyByte[i] = 0xFF;  // Prepare the security key for the read and write operations.
  }
}

void loop() {
  // Look for new cards if not found rerun the loop function
  if (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial()) {
    delay(50);
    return;
  }

  if (!writeMode) {
    Serial.println("RFID Chip detected, reading data from the chip");
    for (uint8_t i = 0; i < 64; i++) {
      readBlock(i, data[i]);
    }
    mfrc522.PICC_DumpToSerial(&(mfrc522.uid));

    for (uint8_t i = 0; i < 4; i++) {
      uidData[i] = data[0][i];
    }

    writeMode = true;
    delay(2000);
    Serial.println("\t*** WRITE MODE ***");
    Serial.println("Scan a MIFARE Classic card to write UID and data");
  } else {
    Serial.println("RFID Chip detected, writing data to the chip");
    // write data to new chip
    for (uint8_t i = 1; i < 64; i++) {
      writeBlock(i, data[i]);
    }

    // Set new UID
    Serial.println("Changing UID:");
    if (mfrc522.MIFARE_SetUid(uidData, (byte)4, true)) {
      Serial.println(F("Wrote new UID to card."));
    }

    // Halt PICC and re-select it so DumpToSerial doesn't get confused
    mfrc522.PICC_HaltA();
    if (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial()) {
      return;
    }

    // Dump the new memory contents
    Serial.println(F("New UID and contents:"));
    mfrc522.PICC_DumpToSerial(&(mfrc522.uid));

    delay(2000);
  }
}
//Write specific block
int writeBlock(int blockNumber, byte arrayAddress[]) {
  //check if the block number corresponds to data block or triler block, rtuen with error if it's trailer block.
  int largestModulo4Number = blockNumber / 4 * 4;
  int trailerBlock = largestModulo4Number + 3;  //determine trailer block for the sector
  if (blockNumber > 2 && (blockNumber + 1) % 4 == 0) {
    Serial.print(blockNumber);
    Serial.println(" is a trailer block: Skipping...");
    return 2;
  }
  //authentication
  byte status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, trailerBlock, &key, &(mfrc522.uid));
  if (status != MFRC522::STATUS_OK) {
    Serial.print("Authentication failed: ");
    Serial.println(mfrc522.GetStatusCodeName(status));
    return 3;  //return "3" as error message
  }
  //writing data to the block
  status = mfrc522.MIFARE_Write(blockNumber, arrayAddress, 16);
  if (status != MFRC522::STATUS_OK) {
    Serial.print("Data write failed: ");
    Serial.println(mfrc522.GetStatusCodeName(status));
    return 4;  //return "4" as error message
  }
  Serial.print("Data written to block ");
  Serial.println(blockNumber);
  return 0;
}
//Read specific block
int readBlock(int blockNumber, byte arrayAddress[]) {
  int largestModulo4Number = blockNumber / 4 * 4;
  int trailerBlock = largestModulo4Number + 3;  //determine trailer block for the sector
  //authentication of the desired block for access
  byte status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, trailerBlock, &key, &(mfrc522.uid));
  if (status != MFRC522::STATUS_OK) {
    Serial.print("Authentication failed : ");
    Serial.println(mfrc522.GetStatusCodeName(status));
    return 3;  //return "3" as error message
  }
  //reading data from the block
  byte buffersize = 18;
  status = mfrc522.MIFARE_Read(blockNumber, arrayAddress, &buffersize);  //&buffersize is a pointer to the buffersize variable; MIFARE_Read requires a pointer instead of just a number
  if (status != MFRC522::STATUS_OK) {
    Serial.print("Data read failed: ");
    Serial.println(mfrc522.GetStatusCodeName(status));
    return 4;  //return "4" as error message
  }
  return 0;
}