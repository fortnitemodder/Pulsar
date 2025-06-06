﻿using ProtoBuf;
using Pulsar.Common.Enums;
using Pulsar.Common.Messages.other;

namespace Pulsar.Common.Messages
{
    [ProtoContract]
    public class SetUserStatus : IMessage
    {
        [ProtoMember(1)]
        public UserStatus Message { get; set; }
    }
}
