/*
A .NET Core TOTP (2FA) Manager with encrypted file storage
Version: 1.0

Encryption: AES (MODE_CBC) with HMAC authentication based on https://gist.github.com/jbtule/4336842

This work (A TOTP Manager with encrypted file storage), is free of known copyright restrictions.
http://creativecommons.org/publicdomain/mark/1.0/

BASIC USAGE:
Display list of saved totp codes: -pw {password}
Add new totp secret: -pw {password} -a {title} {base32 totp secret}
*/


using System;
using System.IO;
using System.Linq;
using McMaster.Extensions.CommandLineUtils;
using Newtonsoft.Json;
using OtpNet;

namespace totp;


public static class Program
{
    private static readonly string _FilePath = Environment.GetEnvironmentVariable("HOME");
    private static readonly string _EncryptedkeysFilename = Path.Join(_FilePath, ".totp_encrypted.txt");
    private static readonly int _DefaultTotpDigits = 6;

    public static void Main(string[] args)
    {
        Console.WriteLine(); // spacing
        string password;
        var itemName = string.Empty;
        var itemSecret = string.Empty;
        var itemDigits = 0;
        var selectedId = 0;

        var app = new CommandLineApplication();

        var optionPassword = app.Option("-pw |--password <password>",
                                        "The password to decrypt the data",
                                        CommandOptionType.SingleValue
        );

        var argAdd = app.Argument("-a",
                                  "Add new totp item: {title} {base32 totp secret} {digits (optional)}",
                                  true
        );

        var optionAdd = app.Option("-a |--add",
                                   "Add new totp item: {title} {base32 totp secret} {digits (optional)}",
                                   CommandOptionType.NoValue
        );

        var optionItemName = app.Option("-title |--title", "Add new totp item title", CommandOptionType.SingleValue);
        var optionSecret = app.Option("-secret |--secret", "Add new totp item secret", CommandOptionType.SingleValue);
        var optionDigits = app.Option("-digits |--digits", "Add new totp item digits", CommandOptionType.SingleValue);
        var optionId = app.Option("-id |--ident", "ID of item to process", CommandOptionType.SingleValue);
        var optionDisplaying = app.Option("-d | --displayorig", "Display original data.", CommandOptionType.NoValue);

        var optionUpdate = app.Option("-u | --update",
                                      "Update an item by ID: -id {ID} -title {title} -secret {base32 totp secret} -digits {digits}",
                                      CommandOptionType.NoValue
        );

        var delete = app.Option("-del |--delete", "Delete an item by ID: -id {ID}", CommandOptionType.NoValue);

        var optionPasswordUpdate = app.Option("-pu |--passwordupdate",
                                              "Update encryption password: {new password}",
                                              CommandOptionType.SingleValue
        );

        app.HelpOption("-? | -hh | --hhelp");

        app.OnExecute(() =>
            {
                if (optionPassword.HasValue())
                {
                    password = optionPassword.Value();

                    if (optionId.HasValue())
                    {
                        if (!int.TryParse(optionId.Value(), out selectedId))
                        {
                            selectedId = 0;
                        }
                    }

                    // item data for adding or editing
                    if (optionItemName.HasValue())
                    {
                        itemName = optionItemName.Value();
                    }

                    if (optionSecret.HasValue())
                    {
                        itemSecret = optionSecret.Value();
                    }

                    if (optionDigits.HasValue())
                    {
                        if (!int.TryParse(optionDigits.Value(), out itemDigits))
                        {
                            itemDigits = 0;
                        }
                    }

                    // main logic
                    if (optionDisplaying.HasValue())
                    {
                        DisplayUnencryptedData(password);
                    }
                    else if (optionAdd.HasValue())
                    {
                        if (argAdd.Values.Count > 0 &&
                            string.IsNullOrEmpty(itemName)) // if individual items not specified then get from add_data
                        {
                            itemName = argAdd.Values[0];

                            if (argAdd.Values.Count > 1)
                            {
                                itemSecret = argAdd.Values[1];

                                if (argAdd.Values.Count > 2)
                                {
                                    if (!int.TryParse(argAdd.Values[2], out itemDigits))
                                    {
                                        itemDigits = 0;
                                    }
                                }
                            }
                        }

                        if (!string.IsNullOrEmpty(itemName) && !string.IsNullOrEmpty(itemSecret))
                        {
                            AddNewItem(password, itemName, itemSecret, itemDigits);
                            DisplayTotpList(password);
                        }
                        else
                        {
                            Console.WriteLine("Missing item data!");
                        }
                    }
                    else if (optionUpdate.HasValue())
                    {
                        if (selectedId > 0)
                        {
                            if (!string.IsNullOrEmpty(itemName) || !string.IsNullOrEmpty(itemSecret) || itemDigits > 0)
                            {
                                UpdateItem(password, selectedId, itemName, itemSecret, itemDigits);
                                DisplayTotpList(password);
                            }
                            else
                            {
                                Console.WriteLine("Missing items to edit!");
                            }
                        }
                        else
                        {
                            Console.WriteLine("ID missing!");
                        }
                    }
                    else if (delete.HasValue())
                    {
                        if (selectedId > 0)
                        {
                            DeleteItem(password, selectedId);
                            DisplayTotpList(password);
                        }
                        else
                        {
                            Console.WriteLine("ID missing!");
                        }
                    }
                    else if (optionPasswordUpdate.HasValue())
                    {
                        UpdatePassword(password, optionPasswordUpdate.Value());
                    }
                    else
                    {
                        DisplayTotpList(password);
                    }
                }
                else
                {
                    Console.WriteLine("Password not specified!");
                    Environment.Exit(-1); // Do not continue
                }

                return 0;
            }
        );

        app.Execute(args);

        Console.WriteLine(); // spacing
    }

    private static void DisplayTotpList(string password)
    {
        var model = LoadAndDecryptToModel(password);
        var nameColumnSpacing = model.Data.Max(x => x.Name.Length) + 4;

        Console.WriteLine("{0}: {1}{2}{3}", "ID", "TITLE", new string(' ', nameColumnSpacing - "TITLE".Length), "TOKEN");

        Console.WriteLine("");

        var itemCount = 1;

        foreach (var item in model.Data)
        {
            var otp = new Totp(ToBytes(item.Secret.Replace(" ", "")));
            var totpString = otp.ComputeTotp();
            var remainingSeconds = otp.RemainingSeconds().ToString();

            Console.WriteLine("{0,2}: {1}{2}{3}{4}Remaining Secs: {5}",
                              itemCount,
                              item.Name,
                              new string(' ', nameColumnSpacing - item.Name.Length),
                              totpString,
                              new string(' ', 6),
                              remainingSeconds
            );

            itemCount++;
        }
    }

    private static void AddNewItem(
        string password,
        string itemName,
        string itemSecret,
        int itemDigits
    )
    {
        if (!string.IsNullOrEmpty(itemName) && !string.IsNullOrEmpty(itemSecret))
        {
            var model = LoadAndDecryptToModel(password);

            if (itemDigits < 1)
            {
                itemDigits = _DefaultTotpDigits;
            }

            var newItem = new TotpObject()
            {
                Name = itemName,
                Secret = itemSecret,
                Digits = itemDigits
            };

            model.Data.Add(newItem);

            SaveAndEncryptObjectToFile(password, model, "*** New item saved ***");
        }
        else
        {
            Console.WriteLine("Missing item data!");
        }
    }

    private static void UpdateItem(
        string password,
        int id,
        string itemName,
        string itemSecret,
        int itemDigits
    )
    {
        var model = LoadAndDecryptToModel(password);

        if (id > 0 && model.Data.Count >= id)
        {
            if (!string.IsNullOrEmpty(itemName))
            {
                model.Data[id - 1].Name = itemName;
            }

            if (!string.IsNullOrEmpty(itemSecret))
            {
                model.Data[id - 1].Secret = itemSecret;
            }

            if (itemDigits > 0)
            {
                model.Data[id - 1].Digits = itemDigits;
            }

            SaveAndEncryptObjectToFile(password, model);
        }
        else
        {
            Console.WriteLine("ID not valid!");
        }
    }

    private static void DeleteItem(string password, int id)
    {
        var model = LoadAndDecryptToModel(password);

        if (id > 0 && model.Data.Count >= id)
        {
            model.Data.RemoveAt(id - 1);
            SaveAndEncryptObjectToFile(password, model, "*** Item Deleted ***");
        }
        else
        {
            Console.WriteLine("ID not valid!");
        }
    }

    private static void UpdatePassword(string password, string newPassword)
    {
        var model = LoadAndDecryptToModel(password);
        SaveAndEncryptObjectToFile(newPassword, model, "*** Password updated ***");
    }

    private static void DisplayUnencryptedData(string password)
    {
        Console.Write(LoadAndDecryptToString(password));
    }

    /*---------------------------------
     * LOADING DATA FUNCTIONS - BEGIN
     * - - - - - - - - - - - - - - - - */
    private static string LoadDataFromFile()
    {
        var result = string.Empty;

        if (System.IO.File.Exists(_EncryptedkeysFilename))
        {
            result = System.IO.File.ReadAllText(_EncryptedkeysFilename);
        }

        return result;
    }

    private static JsonObject LoadAndDecryptToModel(string password)
    {
        var jsonObject = new JsonObject();
        var unencryptedData = LoadAndDecryptToString(password);

        if (!string.IsNullOrEmpty(unencryptedData))
        {
            jsonObject = JsonConvert.DeserializeObject<JsonObject>(unencryptedData);
        }

        return jsonObject;
    }

    private static string LoadAndDecryptToString(string password)
    {
        var encryptedData = LoadDataFromFile();

        if (!string.IsNullOrEmpty(encryptedData))
        {
            var result = AesThenHmac.SimpleDecryptWithPassword(encryptedData, password);

            if (!string.IsNullOrEmpty(result))
            {
                return result;
            }

            Console.WriteLine("Key decryption failed!");
        }
        else
        {
            Console.WriteLine("*** Data file empty ***");
            Console.WriteLine();
        }

        return string.Empty;
    }

    /* - - - - - - - - - - - - - - - -
     * LOADING DATA FUNCTIONS - END
     * -------------------------------*/

    /*---------------------------------
     * SAVING DATA FUNCTIONS - BEGIN
     * - - - - - - - - - - - - - - - - */

    private static void SaveAndEncryptObjectToFile(string password, JsonObject model, string successMsg = "")
    {
        // sort items prior to saving
        model.Data.Sort((x, y) => string.CompareOrdinal(x.Name, y.Name));

        // convert object to json
        var json = JsonConvert.SerializeObject(model);

        //Console.Write(json);

        // encrypt data
        var encryptedResult = AesThenHmac.SimpleEncryptWithPassword(json, password);

        // save to file
        System.IO.File.WriteAllText(_EncryptedkeysFilename, encryptedResult);

        if (!string.IsNullOrEmpty(successMsg))
        {
            Console.WriteLine(successMsg);
            Console.WriteLine(); // spacing
        }
    }

    /* - - - - - - - - - - - - - - - -
     * SAVING DATA FUNCTIONS - END
     * -------------------------------*/

    private static byte[] ToBytes(string input)
    {
        if (string.IsNullOrEmpty(input))
        {
            throw new ArgumentNullException(nameof(input));
        }

        input = input.TrimEnd('=');           //remove padding characters
        var byteCount = input.Length * 5 / 8; //this must be TRUNCATED
        var returnArray = new byte[byteCount];

        byte curByte = 0, bitsRemaining = 8;
        var arrayIndex = 0;

        foreach (var c in input)
        {
            var cValue = CharToValue(c);

            int mask;

            if (bitsRemaining > 5)
            {
                mask = cValue << (bitsRemaining - 5);
                curByte = (byte)(curByte | mask);
                bitsRemaining -= 5;
            }
            else
            {
                mask = cValue >> (5 - bitsRemaining);
                curByte = (byte)(curByte | mask);
                returnArray[arrayIndex++] = curByte;
                curByte = (byte)(cValue << (3 + bitsRemaining));
                bitsRemaining += 3;
            }
        }

        //if we didn't end with a full byte
        if (arrayIndex != byteCount)
        {
            returnArray[arrayIndex] = curByte;
        }

        return returnArray;
    }

    private static int CharToValue(char c)
    {
        var value = (int)c;

        //65-90 == uppercase letters
        if (value is < 91 and > 64)
        {
            return value - 65;
        }

        //50-55 == numbers 2-7
        if (value is < 56 and > 49)
        {
            return value - 24;
        }

        //97-122 == lowercase letters
        if (value is < 123 and > 96)
        {
            return value - 97;
        }

        throw new ArgumentException("Character is not a Base32 character.", nameof(c));
    }
}
