// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: PullPrivateChatRsp.proto

package emu.grasscutter.net.proto;

public final class PullPrivateChatRspOuterClass {
  private PullPrivateChatRspOuterClass() {}
  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistryLite registry) {
  }

  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistry registry) {
    registerAllExtensions(
        (com.google.protobuf.ExtensionRegistryLite) registry);
  }
  public interface PullPrivateChatRspOrBuilder extends
      // @@protoc_insertion_point(interface_extends:PullPrivateChatRsp)
      com.google.protobuf.MessageOrBuilder {

    /**
     * <code>repeated .ChatInfo chat_info = 6;</code>
     */
    java.util.List<emu.grasscutter.net.proto.ChatInfoOuterClass.ChatInfo> 
        getChatInfoList();
    /**
     * <code>repeated .ChatInfo chat_info = 6;</code>
     */
    emu.grasscutter.net.proto.ChatInfoOuterClass.ChatInfo getChatInfo(int index);
    /**
     * <code>repeated .ChatInfo chat_info = 6;</code>
     */
    int getChatInfoCount();
    /**
     * <code>repeated .ChatInfo chat_info = 6;</code>
     */
    java.util.List<? extends emu.grasscutter.net.proto.ChatInfoOuterClass.ChatInfoOrBuilder> 
        getChatInfoOrBuilderList();
    /**
     * <code>repeated .ChatInfo chat_info = 6;</code>
     */
    emu.grasscutter.net.proto.ChatInfoOuterClass.ChatInfoOrBuilder getChatInfoOrBuilder(
        int index);

    /**
     * <code>int32 retcode = 1;</code>
     * @return The retcode.
     */
    int getRetcode();
  }
  /**
   * <pre>
   * enum CmdId {
   *   option allow_alias = true;
   *   NONE = 0;
   *   CMD_ID = 5011;
   *   ENET_CHANNEL_ID = 0;
   *   ENET_IS_RELIABLE = 1;
   * }
   * </pre>
   *
   * Protobuf type {@code PullPrivateChatRsp}
   */
  public static final class PullPrivateChatRsp extends
      com.google.protobuf.GeneratedMessageV3 implements
      // @@protoc_insertion_point(message_implements:PullPrivateChatRsp)
      PullPrivateChatRspOrBuilder {
  private static final long serialVersionUID = 0L;
    // Use PullPrivateChatRsp.newBuilder() to construct.
    private PullPrivateChatRsp(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
      super(builder);
    }
    private PullPrivateChatRsp() {
      chatInfo_ = java.util.Collections.emptyList();
    }

    @java.lang.Override
    @SuppressWarnings({"unused"})
    protected java.lang.Object newInstance(
        UnusedPrivateParameter unused) {
      return new PullPrivateChatRsp();
    }

    @java.lang.Override
    public final com.google.protobuf.UnknownFieldSet
    getUnknownFields() {
      return this.unknownFields;
    }
    private PullPrivateChatRsp(
        com.google.protobuf.CodedInputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      this();
      if (extensionRegistry == null) {
        throw new java.lang.NullPointerException();
      }
      int mutable_bitField0_ = 0;
      com.google.protobuf.UnknownFieldSet.Builder unknownFields =
          com.google.protobuf.UnknownFieldSet.newBuilder();
      try {
        boolean done = false;
        while (!done) {
          int tag = input.readTag();
          switch (tag) {
            case 0:
              done = true;
              break;
            case 8: {

              retcode_ = input.readInt32();
              break;
            }
            case 50: {
              if (!((mutable_bitField0_ & 0x00000001) != 0)) {
                chatInfo_ = new java.util.ArrayList<emu.grasscutter.net.proto.ChatInfoOuterClass.ChatInfo>();
                mutable_bitField0_ |= 0x00000001;
              }
              chatInfo_.add(
                  input.readMessage(emu.grasscutter.net.proto.ChatInfoOuterClass.ChatInfo.parser(), extensionRegistry));
              break;
            }
            default: {
              if (!parseUnknownField(
                  input, unknownFields, extensionRegistry, tag)) {
                done = true;
              }
              break;
            }
          }
        }
      } catch (com.google.protobuf.InvalidProtocolBufferException e) {
        throw e.setUnfinishedMessage(this);
      } catch (java.io.IOException e) {
        throw new com.google.protobuf.InvalidProtocolBufferException(
            e).setUnfinishedMessage(this);
      } finally {
        if (((mutable_bitField0_ & 0x00000001) != 0)) {
          chatInfo_ = java.util.Collections.unmodifiableList(chatInfo_);
        }
        this.unknownFields = unknownFields.build();
        makeExtensionsImmutable();
      }
    }
    public static final com.google.protobuf.Descriptors.Descriptor
        getDescriptor() {
      return emu.grasscutter.net.proto.PullPrivateChatRspOuterClass.internal_static_PullPrivateChatRsp_descriptor;
    }

    @java.lang.Override
    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return emu.grasscutter.net.proto.PullPrivateChatRspOuterClass.internal_static_PullPrivateChatRsp_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              emu.grasscutter.net.proto.PullPrivateChatRspOuterClass.PullPrivateChatRsp.class, emu.grasscutter.net.proto.PullPrivateChatRspOuterClass.PullPrivateChatRsp.Builder.class);
    }

    public static final int CHAT_INFO_FIELD_NUMBER = 6;
    private java.util.List<emu.grasscutter.net.proto.ChatInfoOuterClass.ChatInfo> chatInfo_;
    /**
     * <code>repeated .ChatInfo chat_info = 6;</code>
     */
    @java.lang.Override
    public java.util.List<emu.grasscutter.net.proto.ChatInfoOuterClass.ChatInfo> getChatInfoList() {
      return chatInfo_;
    }
    /**
     * <code>repeated .ChatInfo chat_info = 6;</code>
     */
    @java.lang.Override
    public java.util.List<? extends emu.grasscutter.net.proto.ChatInfoOuterClass.ChatInfoOrBuilder> 
        getChatInfoOrBuilderList() {
      return chatInfo_;
    }
    /**
     * <code>repeated .ChatInfo chat_info = 6;</code>
     */
    @java.lang.Override
    public int getChatInfoCount() {
      return chatInfo_.size();
    }
    /**
     * <code>repeated .ChatInfo chat_info = 6;</code>
     */
    @java.lang.Override
    public emu.grasscutter.net.proto.ChatInfoOuterClass.ChatInfo getChatInfo(int index) {
      return chatInfo_.get(index);
    }
    /**
     * <code>repeated .ChatInfo chat_info = 6;</code>
     */
    @java.lang.Override
    public emu.grasscutter.net.proto.ChatInfoOuterClass.ChatInfoOrBuilder getChatInfoOrBuilder(
        int index) {
      return chatInfo_.get(index);
    }

    public static final int RETCODE_FIELD_NUMBER = 1;
    private int retcode_;
    /**
     * <code>int32 retcode = 1;</code>
     * @return The retcode.
     */
    @java.lang.Override
    public int getRetcode() {
      return retcode_;
    }

    private byte memoizedIsInitialized = -1;
    @java.lang.Override
    public final boolean isInitialized() {
      byte isInitialized = memoizedIsInitialized;
      if (isInitialized == 1) return true;
      if (isInitialized == 0) return false;

      memoizedIsInitialized = 1;
      return true;
    }

    @java.lang.Override
    public void writeTo(com.google.protobuf.CodedOutputStream output)
                        throws java.io.IOException {
      if (retcode_ != 0) {
        output.writeInt32(1, retcode_);
      }
      for (int i = 0; i < chatInfo_.size(); i++) {
        output.writeMessage(6, chatInfo_.get(i));
      }
      unknownFields.writeTo(output);
    }

    @java.lang.Override
    public int getSerializedSize() {
      int size = memoizedSize;
      if (size != -1) return size;

      size = 0;
      if (retcode_ != 0) {
        size += com.google.protobuf.CodedOutputStream
          .computeInt32Size(1, retcode_);
      }
      for (int i = 0; i < chatInfo_.size(); i++) {
        size += com.google.protobuf.CodedOutputStream
          .computeMessageSize(6, chatInfo_.get(i));
      }
      size += unknownFields.getSerializedSize();
      memoizedSize = size;
      return size;
    }

    @java.lang.Override
    public boolean equals(final java.lang.Object obj) {
      if (obj == this) {
       return true;
      }
      if (!(obj instanceof emu.grasscutter.net.proto.PullPrivateChatRspOuterClass.PullPrivateChatRsp)) {
        return super.equals(obj);
      }
      emu.grasscutter.net.proto.PullPrivateChatRspOuterClass.PullPrivateChatRsp other = (emu.grasscutter.net.proto.PullPrivateChatRspOuterClass.PullPrivateChatRsp) obj;

      if (!getChatInfoList()
          .equals(other.getChatInfoList())) return false;
      if (getRetcode()
          != other.getRetcode()) return false;
      if (!unknownFields.equals(other.unknownFields)) return false;
      return true;
    }

    @java.lang.Override
    public int hashCode() {
      if (memoizedHashCode != 0) {
        return memoizedHashCode;
      }
      int hash = 41;
      hash = (19 * hash) + getDescriptor().hashCode();
      if (getChatInfoCount() > 0) {
        hash = (37 * hash) + CHAT_INFO_FIELD_NUMBER;
        hash = (53 * hash) + getChatInfoList().hashCode();
      }
      hash = (37 * hash) + RETCODE_FIELD_NUMBER;
      hash = (53 * hash) + getRetcode();
      hash = (29 * hash) + unknownFields.hashCode();
      memoizedHashCode = hash;
      return hash;
    }

    public static emu.grasscutter.net.proto.PullPrivateChatRspOuterClass.PullPrivateChatRsp parseFrom(
        java.nio.ByteBuffer data)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data);
    }
    public static emu.grasscutter.net.proto.PullPrivateChatRspOuterClass.PullPrivateChatRsp parseFrom(
        java.nio.ByteBuffer data,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data, extensionRegistry);
    }
    public static emu.grasscutter.net.proto.PullPrivateChatRspOuterClass.PullPrivateChatRsp parseFrom(
        com.google.protobuf.ByteString data)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data);
    }
    public static emu.grasscutter.net.proto.PullPrivateChatRspOuterClass.PullPrivateChatRsp parseFrom(
        com.google.protobuf.ByteString data,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data, extensionRegistry);
    }
    public static emu.grasscutter.net.proto.PullPrivateChatRspOuterClass.PullPrivateChatRsp parseFrom(byte[] data)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data);
    }
    public static emu.grasscutter.net.proto.PullPrivateChatRspOuterClass.PullPrivateChatRsp parseFrom(
        byte[] data,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data, extensionRegistry);
    }
    public static emu.grasscutter.net.proto.PullPrivateChatRspOuterClass.PullPrivateChatRsp parseFrom(java.io.InputStream input)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseWithIOException(PARSER, input);
    }
    public static emu.grasscutter.net.proto.PullPrivateChatRspOuterClass.PullPrivateChatRsp parseFrom(
        java.io.InputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseWithIOException(PARSER, input, extensionRegistry);
    }
    public static emu.grasscutter.net.proto.PullPrivateChatRspOuterClass.PullPrivateChatRsp parseDelimitedFrom(java.io.InputStream input)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseDelimitedWithIOException(PARSER, input);
    }
    public static emu.grasscutter.net.proto.PullPrivateChatRspOuterClass.PullPrivateChatRsp parseDelimitedFrom(
        java.io.InputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
    }
    public static emu.grasscutter.net.proto.PullPrivateChatRspOuterClass.PullPrivateChatRsp parseFrom(
        com.google.protobuf.CodedInputStream input)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseWithIOException(PARSER, input);
    }
    public static emu.grasscutter.net.proto.PullPrivateChatRspOuterClass.PullPrivateChatRsp parseFrom(
        com.google.protobuf.CodedInputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseWithIOException(PARSER, input, extensionRegistry);
    }

    @java.lang.Override
    public Builder newBuilderForType() { return newBuilder(); }
    public static Builder newBuilder() {
      return DEFAULT_INSTANCE.toBuilder();
    }
    public static Builder newBuilder(emu.grasscutter.net.proto.PullPrivateChatRspOuterClass.PullPrivateChatRsp prototype) {
      return DEFAULT_INSTANCE.toBuilder().mergeFrom(prototype);
    }
    @java.lang.Override
    public Builder toBuilder() {
      return this == DEFAULT_INSTANCE
          ? new Builder() : new Builder().mergeFrom(this);
    }

    @java.lang.Override
    protected Builder newBuilderForType(
        com.google.protobuf.GeneratedMessageV3.BuilderParent parent) {
      Builder builder = new Builder(parent);
      return builder;
    }
    /**
     * <pre>
     * enum CmdId {
     *   option allow_alias = true;
     *   NONE = 0;
     *   CMD_ID = 5011;
     *   ENET_CHANNEL_ID = 0;
     *   ENET_IS_RELIABLE = 1;
     * }
     * </pre>
     *
     * Protobuf type {@code PullPrivateChatRsp}
     */
    public static final class Builder extends
        com.google.protobuf.GeneratedMessageV3.Builder<Builder> implements
        // @@protoc_insertion_point(builder_implements:PullPrivateChatRsp)
        emu.grasscutter.net.proto.PullPrivateChatRspOuterClass.PullPrivateChatRspOrBuilder {
      public static final com.google.protobuf.Descriptors.Descriptor
          getDescriptor() {
        return emu.grasscutter.net.proto.PullPrivateChatRspOuterClass.internal_static_PullPrivateChatRsp_descriptor;
      }

      @java.lang.Override
      protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
          internalGetFieldAccessorTable() {
        return emu.grasscutter.net.proto.PullPrivateChatRspOuterClass.internal_static_PullPrivateChatRsp_fieldAccessorTable
            .ensureFieldAccessorsInitialized(
                emu.grasscutter.net.proto.PullPrivateChatRspOuterClass.PullPrivateChatRsp.class, emu.grasscutter.net.proto.PullPrivateChatRspOuterClass.PullPrivateChatRsp.Builder.class);
      }

      // Construct using emu.grasscutter.net.proto.PullPrivateChatRspOuterClass.PullPrivateChatRsp.newBuilder()
      private Builder() {
        maybeForceBuilderInitialization();
      }

      private Builder(
          com.google.protobuf.GeneratedMessageV3.BuilderParent parent) {
        super(parent);
        maybeForceBuilderInitialization();
      }
      private void maybeForceBuilderInitialization() {
        if (com.google.protobuf.GeneratedMessageV3
                .alwaysUseFieldBuilders) {
          getChatInfoFieldBuilder();
        }
      }
      @java.lang.Override
      public Builder clear() {
        super.clear();
        if (chatInfoBuilder_ == null) {
          chatInfo_ = java.util.Collections.emptyList();
          bitField0_ = (bitField0_ & ~0x00000001);
        } else {
          chatInfoBuilder_.clear();
        }
        retcode_ = 0;

        return this;
      }

      @java.lang.Override
      public com.google.protobuf.Descriptors.Descriptor
          getDescriptorForType() {
        return emu.grasscutter.net.proto.PullPrivateChatRspOuterClass.internal_static_PullPrivateChatRsp_descriptor;
      }

      @java.lang.Override
      public emu.grasscutter.net.proto.PullPrivateChatRspOuterClass.PullPrivateChatRsp getDefaultInstanceForType() {
        return emu.grasscutter.net.proto.PullPrivateChatRspOuterClass.PullPrivateChatRsp.getDefaultInstance();
      }

      @java.lang.Override
      public emu.grasscutter.net.proto.PullPrivateChatRspOuterClass.PullPrivateChatRsp build() {
        emu.grasscutter.net.proto.PullPrivateChatRspOuterClass.PullPrivateChatRsp result = buildPartial();
        if (!result.isInitialized()) {
          throw newUninitializedMessageException(result);
        }
        return result;
      }

      @java.lang.Override
      public emu.grasscutter.net.proto.PullPrivateChatRspOuterClass.PullPrivateChatRsp buildPartial() {
        emu.grasscutter.net.proto.PullPrivateChatRspOuterClass.PullPrivateChatRsp result = new emu.grasscutter.net.proto.PullPrivateChatRspOuterClass.PullPrivateChatRsp(this);
        int from_bitField0_ = bitField0_;
        if (chatInfoBuilder_ == null) {
          if (((bitField0_ & 0x00000001) != 0)) {
            chatInfo_ = java.util.Collections.unmodifiableList(chatInfo_);
            bitField0_ = (bitField0_ & ~0x00000001);
          }
          result.chatInfo_ = chatInfo_;
        } else {
          result.chatInfo_ = chatInfoBuilder_.build();
        }
        result.retcode_ = retcode_;
        onBuilt();
        return result;
      }

      @java.lang.Override
      public Builder clone() {
        return super.clone();
      }
      @java.lang.Override
      public Builder setField(
          com.google.protobuf.Descriptors.FieldDescriptor field,
          java.lang.Object value) {
        return super.setField(field, value);
      }
      @java.lang.Override
      public Builder clearField(
          com.google.protobuf.Descriptors.FieldDescriptor field) {
        return super.clearField(field);
      }
      @java.lang.Override
      public Builder clearOneof(
          com.google.protobuf.Descriptors.OneofDescriptor oneof) {
        return super.clearOneof(oneof);
      }
      @java.lang.Override
      public Builder setRepeatedField(
          com.google.protobuf.Descriptors.FieldDescriptor field,
          int index, java.lang.Object value) {
        return super.setRepeatedField(field, index, value);
      }
      @java.lang.Override
      public Builder addRepeatedField(
          com.google.protobuf.Descriptors.FieldDescriptor field,
          java.lang.Object value) {
        return super.addRepeatedField(field, value);
      }
      @java.lang.Override
      public Builder mergeFrom(com.google.protobuf.Message other) {
        if (other instanceof emu.grasscutter.net.proto.PullPrivateChatRspOuterClass.PullPrivateChatRsp) {
          return mergeFrom((emu.grasscutter.net.proto.PullPrivateChatRspOuterClass.PullPrivateChatRsp)other);
        } else {
          super.mergeFrom(other);
          return this;
        }
      }

      public Builder mergeFrom(emu.grasscutter.net.proto.PullPrivateChatRspOuterClass.PullPrivateChatRsp other) {
        if (other == emu.grasscutter.net.proto.PullPrivateChatRspOuterClass.PullPrivateChatRsp.getDefaultInstance()) return this;
        if (chatInfoBuilder_ == null) {
          if (!other.chatInfo_.isEmpty()) {
            if (chatInfo_.isEmpty()) {
              chatInfo_ = other.chatInfo_;
              bitField0_ = (bitField0_ & ~0x00000001);
            } else {
              ensureChatInfoIsMutable();
              chatInfo_.addAll(other.chatInfo_);
            }
            onChanged();
          }
        } else {
          if (!other.chatInfo_.isEmpty()) {
            if (chatInfoBuilder_.isEmpty()) {
              chatInfoBuilder_.dispose();
              chatInfoBuilder_ = null;
              chatInfo_ = other.chatInfo_;
              bitField0_ = (bitField0_ & ~0x00000001);
              chatInfoBuilder_ = 
                com.google.protobuf.GeneratedMessageV3.alwaysUseFieldBuilders ?
                   getChatInfoFieldBuilder() : null;
            } else {
              chatInfoBuilder_.addAllMessages(other.chatInfo_);
            }
          }
        }
        if (other.getRetcode() != 0) {
          setRetcode(other.getRetcode());
        }
        this.mergeUnknownFields(other.unknownFields);
        onChanged();
        return this;
      }

      @java.lang.Override
      public final boolean isInitialized() {
        return true;
      }

      @java.lang.Override
      public Builder mergeFrom(
          com.google.protobuf.CodedInputStream input,
          com.google.protobuf.ExtensionRegistryLite extensionRegistry)
          throws java.io.IOException {
        emu.grasscutter.net.proto.PullPrivateChatRspOuterClass.PullPrivateChatRsp parsedMessage = null;
        try {
          parsedMessage = PARSER.parsePartialFrom(input, extensionRegistry);
        } catch (com.google.protobuf.InvalidProtocolBufferException e) {
          parsedMessage = (emu.grasscutter.net.proto.PullPrivateChatRspOuterClass.PullPrivateChatRsp) e.getUnfinishedMessage();
          throw e.unwrapIOException();
        } finally {
          if (parsedMessage != null) {
            mergeFrom(parsedMessage);
          }
        }
        return this;
      }
      private int bitField0_;

      private java.util.List<emu.grasscutter.net.proto.ChatInfoOuterClass.ChatInfo> chatInfo_ =
        java.util.Collections.emptyList();
      private void ensureChatInfoIsMutable() {
        if (!((bitField0_ & 0x00000001) != 0)) {
          chatInfo_ = new java.util.ArrayList<emu.grasscutter.net.proto.ChatInfoOuterClass.ChatInfo>(chatInfo_);
          bitField0_ |= 0x00000001;
         }
      }

      private com.google.protobuf.RepeatedFieldBuilderV3<
          emu.grasscutter.net.proto.ChatInfoOuterClass.ChatInfo, emu.grasscutter.net.proto.ChatInfoOuterClass.ChatInfo.Builder, emu.grasscutter.net.proto.ChatInfoOuterClass.ChatInfoOrBuilder> chatInfoBuilder_;

      /**
       * <code>repeated .ChatInfo chat_info = 6;</code>
       */
      public java.util.List<emu.grasscutter.net.proto.ChatInfoOuterClass.ChatInfo> getChatInfoList() {
        if (chatInfoBuilder_ == null) {
          return java.util.Collections.unmodifiableList(chatInfo_);
        } else {
          return chatInfoBuilder_.getMessageList();
        }
      }
      /**
       * <code>repeated .ChatInfo chat_info = 6;</code>
       */
      public int getChatInfoCount() {
        if (chatInfoBuilder_ == null) {
          return chatInfo_.size();
        } else {
          return chatInfoBuilder_.getCount();
        }
      }
      /**
       * <code>repeated .ChatInfo chat_info = 6;</code>
       */
      public emu.grasscutter.net.proto.ChatInfoOuterClass.ChatInfo getChatInfo(int index) {
        if (chatInfoBuilder_ == null) {
          return chatInfo_.get(index);
        } else {
          return chatInfoBuilder_.getMessage(index);
        }
      }
      /**
       * <code>repeated .ChatInfo chat_info = 6;</code>
       */
      public Builder setChatInfo(
          int index, emu.grasscutter.net.proto.ChatInfoOuterClass.ChatInfo value) {
        if (chatInfoBuilder_ == null) {
          if (value == null) {
            throw new NullPointerException();
          }
          ensureChatInfoIsMutable();
          chatInfo_.set(index, value);
          onChanged();
        } else {
          chatInfoBuilder_.setMessage(index, value);
        }
        return this;
      }
      /**
       * <code>repeated .ChatInfo chat_info = 6;</code>
       */
      public Builder setChatInfo(
          int index, emu.grasscutter.net.proto.ChatInfoOuterClass.ChatInfo.Builder builderForValue) {
        if (chatInfoBuilder_ == null) {
          ensureChatInfoIsMutable();
          chatInfo_.set(index, builderForValue.build());
          onChanged();
        } else {
          chatInfoBuilder_.setMessage(index, builderForValue.build());
        }
        return this;
      }
      /**
       * <code>repeated .ChatInfo chat_info = 6;</code>
       */
      public Builder addChatInfo(emu.grasscutter.net.proto.ChatInfoOuterClass.ChatInfo value) {
        if (chatInfoBuilder_ == null) {
          if (value == null) {
            throw new NullPointerException();
          }
          ensureChatInfoIsMutable();
          chatInfo_.add(value);
          onChanged();
        } else {
          chatInfoBuilder_.addMessage(value);
        }
        return this;
      }
      /**
       * <code>repeated .ChatInfo chat_info = 6;</code>
       */
      public Builder addChatInfo(
          int index, emu.grasscutter.net.proto.ChatInfoOuterClass.ChatInfo value) {
        if (chatInfoBuilder_ == null) {
          if (value == null) {
            throw new NullPointerException();
          }
          ensureChatInfoIsMutable();
          chatInfo_.add(index, value);
          onChanged();
        } else {
          chatInfoBuilder_.addMessage(index, value);
        }
        return this;
      }
      /**
       * <code>repeated .ChatInfo chat_info = 6;</code>
       */
      public Builder addChatInfo(
          emu.grasscutter.net.proto.ChatInfoOuterClass.ChatInfo.Builder builderForValue) {
        if (chatInfoBuilder_ == null) {
          ensureChatInfoIsMutable();
          chatInfo_.add(builderForValue.build());
          onChanged();
        } else {
          chatInfoBuilder_.addMessage(builderForValue.build());
        }
        return this;
      }
      /**
       * <code>repeated .ChatInfo chat_info = 6;</code>
       */
      public Builder addChatInfo(
          int index, emu.grasscutter.net.proto.ChatInfoOuterClass.ChatInfo.Builder builderForValue) {
        if (chatInfoBuilder_ == null) {
          ensureChatInfoIsMutable();
          chatInfo_.add(index, builderForValue.build());
          onChanged();
        } else {
          chatInfoBuilder_.addMessage(index, builderForValue.build());
        }
        return this;
      }
      /**
       * <code>repeated .ChatInfo chat_info = 6;</code>
       */
      public Builder addAllChatInfo(
          java.lang.Iterable<? extends emu.grasscutter.net.proto.ChatInfoOuterClass.ChatInfo> values) {
        if (chatInfoBuilder_ == null) {
          ensureChatInfoIsMutable();
          com.google.protobuf.AbstractMessageLite.Builder.addAll(
              values, chatInfo_);
          onChanged();
        } else {
          chatInfoBuilder_.addAllMessages(values);
        }
        return this;
      }
      /**
       * <code>repeated .ChatInfo chat_info = 6;</code>
       */
      public Builder clearChatInfo() {
        if (chatInfoBuilder_ == null) {
          chatInfo_ = java.util.Collections.emptyList();
          bitField0_ = (bitField0_ & ~0x00000001);
          onChanged();
        } else {
          chatInfoBuilder_.clear();
        }
        return this;
      }
      /**
       * <code>repeated .ChatInfo chat_info = 6;</code>
       */
      public Builder removeChatInfo(int index) {
        if (chatInfoBuilder_ == null) {
          ensureChatInfoIsMutable();
          chatInfo_.remove(index);
          onChanged();
        } else {
          chatInfoBuilder_.remove(index);
        }
        return this;
      }
      /**
       * <code>repeated .ChatInfo chat_info = 6;</code>
       */
      public emu.grasscutter.net.proto.ChatInfoOuterClass.ChatInfo.Builder getChatInfoBuilder(
          int index) {
        return getChatInfoFieldBuilder().getBuilder(index);
      }
      /**
       * <code>repeated .ChatInfo chat_info = 6;</code>
       */
      public emu.grasscutter.net.proto.ChatInfoOuterClass.ChatInfoOrBuilder getChatInfoOrBuilder(
          int index) {
        if (chatInfoBuilder_ == null) {
          return chatInfo_.get(index);  } else {
          return chatInfoBuilder_.getMessageOrBuilder(index);
        }
      }
      /**
       * <code>repeated .ChatInfo chat_info = 6;</code>
       */
      public java.util.List<? extends emu.grasscutter.net.proto.ChatInfoOuterClass.ChatInfoOrBuilder> 
           getChatInfoOrBuilderList() {
        if (chatInfoBuilder_ != null) {
          return chatInfoBuilder_.getMessageOrBuilderList();
        } else {
          return java.util.Collections.unmodifiableList(chatInfo_);
        }
      }
      /**
       * <code>repeated .ChatInfo chat_info = 6;</code>
       */
      public emu.grasscutter.net.proto.ChatInfoOuterClass.ChatInfo.Builder addChatInfoBuilder() {
        return getChatInfoFieldBuilder().addBuilder(
            emu.grasscutter.net.proto.ChatInfoOuterClass.ChatInfo.getDefaultInstance());
      }
      /**
       * <code>repeated .ChatInfo chat_info = 6;</code>
       */
      public emu.grasscutter.net.proto.ChatInfoOuterClass.ChatInfo.Builder addChatInfoBuilder(
          int index) {
        return getChatInfoFieldBuilder().addBuilder(
            index, emu.grasscutter.net.proto.ChatInfoOuterClass.ChatInfo.getDefaultInstance());
      }
      /**
       * <code>repeated .ChatInfo chat_info = 6;</code>
       */
      public java.util.List<emu.grasscutter.net.proto.ChatInfoOuterClass.ChatInfo.Builder> 
           getChatInfoBuilderList() {
        return getChatInfoFieldBuilder().getBuilderList();
      }
      private com.google.protobuf.RepeatedFieldBuilderV3<
          emu.grasscutter.net.proto.ChatInfoOuterClass.ChatInfo, emu.grasscutter.net.proto.ChatInfoOuterClass.ChatInfo.Builder, emu.grasscutter.net.proto.ChatInfoOuterClass.ChatInfoOrBuilder> 
          getChatInfoFieldBuilder() {
        if (chatInfoBuilder_ == null) {
          chatInfoBuilder_ = new com.google.protobuf.RepeatedFieldBuilderV3<
              emu.grasscutter.net.proto.ChatInfoOuterClass.ChatInfo, emu.grasscutter.net.proto.ChatInfoOuterClass.ChatInfo.Builder, emu.grasscutter.net.proto.ChatInfoOuterClass.ChatInfoOrBuilder>(
                  chatInfo_,
                  ((bitField0_ & 0x00000001) != 0),
                  getParentForChildren(),
                  isClean());
          chatInfo_ = null;
        }
        return chatInfoBuilder_;
      }

      private int retcode_ ;
      /**
       * <code>int32 retcode = 1;</code>
       * @return The retcode.
       */
      @java.lang.Override
      public int getRetcode() {
        return retcode_;
      }
      /**
       * <code>int32 retcode = 1;</code>
       * @param value The retcode to set.
       * @return This builder for chaining.
       */
      public Builder setRetcode(int value) {
        
        retcode_ = value;
        onChanged();
        return this;
      }
      /**
       * <code>int32 retcode = 1;</code>
       * @return This builder for chaining.
       */
      public Builder clearRetcode() {
        
        retcode_ = 0;
        onChanged();
        return this;
      }
      @java.lang.Override
      public final Builder setUnknownFields(
          final com.google.protobuf.UnknownFieldSet unknownFields) {
        return super.setUnknownFields(unknownFields);
      }

      @java.lang.Override
      public final Builder mergeUnknownFields(
          final com.google.protobuf.UnknownFieldSet unknownFields) {
        return super.mergeUnknownFields(unknownFields);
      }


      // @@protoc_insertion_point(builder_scope:PullPrivateChatRsp)
    }

    // @@protoc_insertion_point(class_scope:PullPrivateChatRsp)
    private static final emu.grasscutter.net.proto.PullPrivateChatRspOuterClass.PullPrivateChatRsp DEFAULT_INSTANCE;
    static {
      DEFAULT_INSTANCE = new emu.grasscutter.net.proto.PullPrivateChatRspOuterClass.PullPrivateChatRsp();
    }

    public static emu.grasscutter.net.proto.PullPrivateChatRspOuterClass.PullPrivateChatRsp getDefaultInstance() {
      return DEFAULT_INSTANCE;
    }

    private static final com.google.protobuf.Parser<PullPrivateChatRsp>
        PARSER = new com.google.protobuf.AbstractParser<PullPrivateChatRsp>() {
      @java.lang.Override
      public PullPrivateChatRsp parsePartialFrom(
          com.google.protobuf.CodedInputStream input,
          com.google.protobuf.ExtensionRegistryLite extensionRegistry)
          throws com.google.protobuf.InvalidProtocolBufferException {
        return new PullPrivateChatRsp(input, extensionRegistry);
      }
    };

    public static com.google.protobuf.Parser<PullPrivateChatRsp> parser() {
      return PARSER;
    }

    @java.lang.Override
    public com.google.protobuf.Parser<PullPrivateChatRsp> getParserForType() {
      return PARSER;
    }

    @java.lang.Override
    public emu.grasscutter.net.proto.PullPrivateChatRspOuterClass.PullPrivateChatRsp getDefaultInstanceForType() {
      return DEFAULT_INSTANCE;
    }

  }

  private static final com.google.protobuf.Descriptors.Descriptor
    internal_static_PullPrivateChatRsp_descriptor;
  private static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_PullPrivateChatRsp_fieldAccessorTable;

  public static com.google.protobuf.Descriptors.FileDescriptor
      getDescriptor() {
    return descriptor;
  }
  private static  com.google.protobuf.Descriptors.FileDescriptor
      descriptor;
  static {
    java.lang.String[] descriptorData = {
      "\n\030PullPrivateChatRsp.proto\032\016ChatInfo.pro" +
      "to\"C\n\022PullPrivateChatRsp\022\034\n\tchat_info\030\006 " +
      "\003(\0132\t.ChatInfo\022\017\n\007retcode\030\001 \001(\005B\033\n\031emu.g" +
      "rasscutter.net.protob\006proto3"
    };
    descriptor = com.google.protobuf.Descriptors.FileDescriptor
      .internalBuildGeneratedFileFrom(descriptorData,
        new com.google.protobuf.Descriptors.FileDescriptor[] {
          emu.grasscutter.net.proto.ChatInfoOuterClass.getDescriptor(),
        });
    internal_static_PullPrivateChatRsp_descriptor =
      getDescriptor().getMessageTypes().get(0);
    internal_static_PullPrivateChatRsp_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_PullPrivateChatRsp_descriptor,
        new java.lang.String[] { "ChatInfo", "Retcode", });
    emu.grasscutter.net.proto.ChatInfoOuterClass.getDescriptor();
  }

  // @@protoc_insertion_point(outer_class_scope)
}
