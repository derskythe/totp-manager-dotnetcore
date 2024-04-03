using System.Collections.Generic;

namespace totp;


public class JsonObject
{
    public List<TotpObject> Data { get; set; } = new();
}
