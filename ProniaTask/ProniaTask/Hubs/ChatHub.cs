using Microsoft.AspNetCore.SignalR;

namespace ProniaTask.Hubs
{
    public class ChatHub:Hub
    {
        IHttpContextAccessor _accessor;

        public ChatHub(IHttpContextAccessor httpContextAccessor)
        {
            _accessor = httpContextAccessor;
        }

        public async Task SendMessage(string message)
        {
            string username = string.Empty;
            if (_accessor.HttpContext.User.Identity.IsAuthenticated)
            {
             username = _accessor.HttpContext.User.Identity.Name;

            }
            else
            {
                throw new Exception();
            }
            await Clients.All.SendAsync("ReceiveMessage",username, message);
        }
        public override async Task OnConnectedAsync()
        {
            await Clients.All.SendAsync("SetOnline", _accessor.HttpContext.User.Identity.Name);
            await base.OnConnectedAsync();
        }
    }
}
