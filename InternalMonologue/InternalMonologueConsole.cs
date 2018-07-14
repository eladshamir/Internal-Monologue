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
            if (response.Resp1.IsNullOrWhiteSpace())
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
            if (s.IsNullOrWhiteSpace())
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
