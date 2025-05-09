﻿using ProtoBuf;
using Pulsar.Common.Messages.other;

namespace Pulsar.Common.Messages
{
    [ProtoContract]
    public class SetStatus : IMessage
    {
        [ProtoMember(1)]
        public string Message { get; set; }
    }
}
