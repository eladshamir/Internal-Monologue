using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace InternalMonologue
{
    //this is hack to support .net 3.5 (default installation on Windows 7)
    public static class StringExtensions
    {
        public static bool IsNullOrWhiteSpace(this string value)
        {
            if (value == null) return true;
            return string.IsNullOrEmpty(value.Trim());
        }
    }
}
