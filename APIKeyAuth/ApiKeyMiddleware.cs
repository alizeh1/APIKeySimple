namespace APIKeyAuth
{
    public class ApiKeyMiddleware
    {
        private readonly RequestDelegate _next;  //This is an instance of RequestDelegate
        private const string APIKEY = "XApiKey"; //This constant string represents the name of the API key in the HTTP headers. In this case, it's set to "XApiKey."
        public ApiKeyMiddleware(RequestDelegate next)
        {
            _next = next;
        }
        public async Task InvokeAsync(HttpContext context)
        {
            if (!context.Request.Headers.TryGetValue(APIKEY, out
                    var extractedApiKey))
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsync("Api Key was not provided ");
                return;
            }
            var appSettings = context.RequestServices.GetRequiredService<IConfiguration>();
            var apiKey = appSettings.GetValue<string>(APIKEY);
            if (!apiKey.Equals(extractedApiKey))
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsync("Unauthorized client");
                return;
            }
            await _next(context); //If the API key is successfully validated, the middleware calls the next middleware in the pipeline.
        }
    }
}
