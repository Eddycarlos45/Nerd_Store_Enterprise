namespace NSE.Identity.API.Extensions
{
    public class AppSettings
    {
        public string Secret { get; set; }
        public int ExpirationTime { get; set; }
        public string Sender { get; set; }
        public string ValidIn { get; set; }
    }
}
