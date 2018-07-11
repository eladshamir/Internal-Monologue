using System;
using System.Collections.Generic;
using System.Text;

namespace InternalMonologue
{
    public class InternalMonologueConsole
    {
        private string output = "";
        public List<InternalMonologueResponse> Responses = new List<InternalMonologueResponse>();
        public void AddResponse(InternalMonologueResponse response)
        {
            if (string.IsNullOrWhiteSpace(response.Resp1))
            {
                return;
            }
            Responses.Add(response);
        }
        public void AddResponses(List<InternalMonologueResponse> responses)
        {
            foreach (var response in responses)
            {
                AddResponse(response);
            }
        }
        public void AddConsole(string s)
        {
            if (string.IsNullOrWhiteSpace(s))
            {
                return;
            }
            output += s;
        }
        public string Output()
        {
            return output;
        }
    }
}
