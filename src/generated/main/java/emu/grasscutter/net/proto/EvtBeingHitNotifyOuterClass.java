// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: EvtBeingHitNotify.proto

package emu.grasscutter.net.proto;

public final class EvtBeingHitNotifyOuterClass {
  private EvtBeingHitNotifyOuterClass() {}
  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistryLite registry) {
  }

  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistry registry) {
    registerAllExtensions(
        (com.google.protobuf.ExtensionRegistryLite) registry);
  }
  public interface EvtBeingHitNotifyOrBuilder extends
      // @@protoc_insertion_point(interface_extends:EvtBeingHitNotify)
      com.google.protobuf.MessageOrBuilder {

    /**
     * <code>.EvtBeingHitInfo being_hit_info = 12;</code>
     * @return Whether the beingHitInfo field is set.
     */
    boolean hasBeingHitInfo();
    /**
     * <code>.EvtBeingHitInfo being_hit_info = 12;</code>
     * @return The beingHitInfo.
     */
    emu.grasscutter.net.proto.EvtBeingHitInfoOuterClass.EvtBeingHitInfo getBeingHitInfo();
    /**
     * <code>.EvtBeingHitInfo being_hit_info = 12;</code>
     */
    emu.grasscutter.net.proto.EvtBeingHitInfoOuterClass.EvtBeingHitInfoOrBuilder getBeingHitInfoOrBuilder();

    /**
     * <code>.ForwardType forward_type = 11;</code>
     * @return The enum numeric value on the wire for forwardType.
     */
    int getForwardTypeValue();
    /**
     * <code>.ForwardType forward_type = 11;</code>
     * @return The forwardType.
     */
    emu.grasscutter.net.proto.ForwardTypeOuterClass.ForwardType getForwardType();
  }
  /**
   * <pre>
   * enum CmdId {
   *   option allow_alias = true;
   *   NONE = 0;
   *   CMD_ID = 379;
   *   ENET_CHANNEL_ID = 0;
   *   ENET_IS_RELIABLE = 1;
   *   IS_ALLOW_CLIENT = 1;
   * }
   * </pre>
   *
   * Protobuf type {@code EvtBeingHitNotify}
   */
  public static final class EvtBeingHitNotify extends
      com.google.protobuf.GeneratedMessageV3 implements
      // @@protoc_insertion_point(message_implements:EvtBeingHitNotify)
      EvtBeingHitNotifyOrBuilder {
  private static final long serialVersionUID = 0L;
    // Use EvtBeingHitNotify.newBuilder() to construct.
    private EvtBeingHitNotify(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
      super(builder);
    }
    private EvtBeingHitNotify() {
      forwardType_ = 0;
    }

    @java.lang.Override
    @SuppressWarnings({"unused"})
    protected java.lang.Object newInstance(
        UnusedPrivateParameter unused) {
      return new EvtBeingHitNotify();
    }

    @java.lang.Override
    public final com.google.protobuf.UnknownFieldSet
    getUnknownFields() {
      return this.unknownFields;
    }
    private EvtBeingHitNotify(
        com.google.protobuf.CodedInputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      this();
      if (extensionRegistry == null) {
        throw new java.lang.NullPointerException();
      }
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
            case 88: {
              int rawValue = input.readEnum();

              forwardType_ = rawValue;
              break;
            }
            case 98: {
              emu.grasscutter.net.proto.EvtBeingHitInfoOuterClass.EvtBeingHitInfo.Builder subBuilder = null;
              if (beingHitInfo_ != null) {
                subBuilder = beingHitInfo_.toBuilder();
              }
              beingHitInfo_ = input.readMessage(emu.grasscutter.net.proto.EvtBeingHitInfoOuterClass.EvtBeingHitInfo.parser(), extensionRegistry);
              if (subBuilder != null) {
                subBuilder.mergeFrom(beingHitInfo_);
                beingHitInfo_ = subBuilder.buildPartial();
              }

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
        this.unknownFields = unknownFields.build();
        makeExtensionsImmutable();
      }
    }
    public static final com.google.protobuf.Descriptors.Descriptor
        getDescriptor() {
      return emu.grasscutter.net.proto.EvtBeingHitNotifyOuterClass.internal_static_EvtBeingHitNotify_descriptor;
    }

    @java.lang.Override
    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return emu.grasscutter.net.proto.EvtBeingHitNotifyOuterClass.internal_static_EvtBeingHitNotify_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              emu.grasscutter.net.proto.EvtBeingHitNotifyOuterClass.EvtBeingHitNotify.class, emu.grasscutter.net.proto.EvtBeingHitNotifyOuterClass.EvtBeingHitNotify.Builder.class);
    }

    public static final int BEING_HIT_INFO_FIELD_NUMBER = 12;
    private emu.grasscutter.net.proto.EvtBeingHitInfoOuterClass.EvtBeingHitInfo beingHitInfo_;
    /**
     * <code>.EvtBeingHitInfo being_hit_info = 12;</code>
     * @return Whether the beingHitInfo field is set.
     */
    @java.lang.Override
    public boolean hasBeingHitInfo() {
      return beingHitInfo_ != null;
    }
    /**
     * <code>.EvtBeingHitInfo being_hit_info = 12;</code>
     * @return The beingHitInfo.
     */
    @java.lang.Override
    public emu.grasscutter.net.proto.EvtBeingHitInfoOuterClass.EvtBeingHitInfo getBeingHitInfo() {
      return beingHitInfo_ == null ? emu.grasscutter.net.proto.EvtBeingHitInfoOuterClass.EvtBeingHitInfo.getDefaultInstance() : beingHitInfo_;
    }
    /**
     * <code>.EvtBeingHitInfo being_hit_info = 12;</code>
     */
    @java.lang.Override
    public emu.grasscutter.net.proto.EvtBeingHitInfoOuterClass.EvtBeingHitInfoOrBuilder getBeingHitInfoOrBuilder() {
      return getBeingHitInfo();
    }

    public static final int FORWARD_TYPE_FIELD_NUMBER = 11;
    private int forwardType_;
    /**
     * <code>.ForwardType forward_type = 11;</code>
     * @return The enum numeric value on the wire for forwardType.
     */
    @java.lang.Override public int getForwardTypeValue() {
      return forwardType_;
    }
    /**
     * <code>.ForwardType forward_type = 11;</code>
     * @return The forwardType.
     */
    @java.lang.Override public emu.grasscutter.net.proto.ForwardTypeOuterClass.ForwardType getForwardType() {
      @SuppressWarnings("deprecation")
      emu.grasscutter.net.proto.ForwardTypeOuterClass.ForwardType result = emu.grasscutter.net.proto.ForwardTypeOuterClass.ForwardType.valueOf(forwardType_);
      return result == null ? emu.grasscutter.net.proto.ForwardTypeOuterClass.ForwardType.UNRECOGNIZED : result;
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
      if (forwardType_ != emu.grasscutter.net.proto.ForwardTypeOuterClass.ForwardType.FORWARD_TYPE_LOCAL.getNumber()) {
        output.writeEnum(11, forwardType_);
      }
      if (beingHitInfo_ != null) {
        output.writeMessage(12, getBeingHitInfo());
      }
      unknownFields.writeTo(output);
    }

    @java.lang.Override
    public int getSerializedSize() {
      int size = memoizedSize;
      if (size != -1) return size;

      size = 0;
      if (forwardType_ != emu.grasscutter.net.proto.ForwardTypeOuterClass.ForwardType.FORWARD_TYPE_LOCAL.getNumber()) {
        size += com.google.protobuf.CodedOutputStream
          .computeEnumSize(11, forwardType_);
      }
      if (beingHitInfo_ != null) {
        size += com.google.protobuf.CodedOutputStream
          .computeMessageSize(12, getBeingHitInfo());
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
      if (!(obj instanceof emu.grasscutter.net.proto.EvtBeingHitNotifyOuterClass.EvtBeingHitNotify)) {
        return super.equals(obj);
      }
      emu.grasscutter.net.proto.EvtBeingHitNotifyOuterClass.EvtBeingHitNotify other = (emu.grasscutter.net.proto.EvtBeingHitNotifyOuterClass.EvtBeingHitNotify) obj;

      if (hasBeingHitInfo() != other.hasBeingHitInfo()) return false;
      if (hasBeingHitInfo()) {
        if (!getBeingHitInfo()
            .equals(other.getBeingHitInfo())) return false;
      }
      if (forwardType_ != other.forwardType_) return false;
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
      if (hasBeingHitInfo()) {
        hash = (37 * hash) + BEING_HIT_INFO_FIELD_NUMBER;
        hash = (53 * hash) + getBeingHitInfo().hashCode();
      }
      hash = (37 * hash) + FORWARD_TYPE_FIELD_NUMBER;
      hash = (53 * hash) + forwardType_;
      hash = (29 * hash) + unknownFields.hashCode();
      memoizedHashCode = hash;
      return hash;
    }

    public static emu.grasscutter.net.proto.EvtBeingHitNotifyOuterClass.EvtBeingHitNotify parseFrom(
        java.nio.ByteBuffer data)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data);
    }
    public static emu.grasscutter.net.proto.EvtBeingHitNotifyOuterClass.EvtBeingHitNotify parseFrom(
        java.nio.ByteBuffer data,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data, extensionRegistry);
    }
    public static emu.grasscutter.net.proto.EvtBeingHitNotifyOuterClass.EvtBeingHitNotify parseFrom(
        com.google.protobuf.ByteString data)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data);
    }
    public static emu.grasscutter.net.proto.EvtBeingHitNotifyOuterClass.EvtBeingHitNotify parseFrom(
        com.google.protobuf.ByteString data,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data, extensionRegistry);
    }
    public static emu.grasscutter.net.proto.EvtBeingHitNotifyOuterClass.EvtBeingHitNotify parseFrom(byte[] data)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data);
    }
    public static emu.grasscutter.net.proto.EvtBeingHitNotifyOuterClass.EvtBeingHitNotify parseFrom(
        byte[] data,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data, extensionRegistry);
    }
    public static emu.grasscutter.net.proto.EvtBeingHitNotifyOuterClass.EvtBeingHitNotify parseFrom(java.io.InputStream input)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseWithIOException(PARSER, input);
    }
    public static emu.grasscutter.net.proto.EvtBeingHitNotifyOuterClass.EvtBeingHitNotify parseFrom(
        java.io.InputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseWithIOException(PARSER, input, extensionRegistry);
    }
    public static emu.grasscutter.net.proto.EvtBeingHitNotifyOuterClass.EvtBeingHitNotify parseDelimitedFrom(java.io.InputStream input)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseDelimitedWithIOException(PARSER, input);
    }
    public static emu.grasscutter.net.proto.EvtBeingHitNotifyOuterClass.EvtBeingHitNotify parseDelimitedFrom(
        java.io.InputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
    }
    public static emu.grasscutter.net.proto.EvtBeingHitNotifyOuterClass.EvtBeingHitNotify parseFrom(
        com.google.protobuf.CodedInputStream input)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseWithIOException(PARSER, input);
    }
    public static emu.grasscutter.net.proto.EvtBeingHitNotifyOuterClass.EvtBeingHitNotify parseFrom(
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
    public static Builder newBuilder(emu.grasscutter.net.proto.EvtBeingHitNotifyOuterClass.EvtBeingHitNotify prototype) {
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
     *   CMD_ID = 379;
     *   ENET_CHANNEL_ID = 0;
     *   ENET_IS_RELIABLE = 1;
     *   IS_ALLOW_CLIENT = 1;
     * }
     * </pre>
     *
     * Protobuf type {@code EvtBeingHitNotify}
     */
    public static final class Builder extends
        com.google.protobuf.GeneratedMessageV3.Builder<Builder> implements
        // @@protoc_insertion_point(builder_implements:EvtBeingHitNotify)
        emu.grasscutter.net.proto.EvtBeingHitNotifyOuterClass.EvtBeingHitNotifyOrBuilder {
      public static final com.google.protobuf.Descriptors.Descriptor
          getDescriptor() {
        return emu.grasscutter.net.proto.EvtBeingHitNotifyOuterClass.internal_static_EvtBeingHitNotify_descriptor;
      }

      @java.lang.Override
      protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
          internalGetFieldAccessorTable() {
        return emu.grasscutter.net.proto.EvtBeingHitNotifyOuterClass.internal_static_EvtBeingHitNotify_fieldAccessorTable
            .ensureFieldAccessorsInitialized(
                emu.grasscutter.net.proto.EvtBeingHitNotifyOuterClass.EvtBeingHitNotify.class, emu.grasscutter.net.proto.EvtBeingHitNotifyOuterClass.EvtBeingHitNotify.Builder.class);
      }

      // Construct using emu.grasscutter.net.proto.EvtBeingHitNotifyOuterClass.EvtBeingHitNotify.newBuilder()
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
        }
      }
      @java.lang.Override
      public Builder clear() {
        super.clear();
        if (beingHitInfoBuilder_ == null) {
          beingHitInfo_ = null;
        } else {
          beingHitInfo_ = null;
          beingHitInfoBuilder_ = null;
        }
        forwardType_ = 0;

        return this;
      }

      @java.lang.Override
      public com.google.protobuf.Descriptors.Descriptor
          getDescriptorForType() {
        return emu.grasscutter.net.proto.EvtBeingHitNotifyOuterClass.internal_static_EvtBeingHitNotify_descriptor;
      }

      @java.lang.Override
      public emu.grasscutter.net.proto.EvtBeingHitNotifyOuterClass.EvtBeingHitNotify getDefaultInstanceForType() {
        return emu.grasscutter.net.proto.EvtBeingHitNotifyOuterClass.EvtBeingHitNotify.getDefaultInstance();
      }

      @java.lang.Override
      public emu.grasscutter.net.proto.EvtBeingHitNotifyOuterClass.EvtBeingHitNotify build() {
        emu.grasscutter.net.proto.EvtBeingHitNotifyOuterClass.EvtBeingHitNotify result = buildPartial();
        if (!result.isInitialized()) {
          throw newUninitializedMessageException(result);
        }
        return result;
      }

      @java.lang.Override
      public emu.grasscutter.net.proto.EvtBeingHitNotifyOuterClass.EvtBeingHitNotify buildPartial() {
        emu.grasscutter.net.proto.EvtBeingHitNotifyOuterClass.EvtBeingHitNotify result = new emu.grasscutter.net.proto.EvtBeingHitNotifyOuterClass.EvtBeingHitNotify(this);
        if (beingHitInfoBuilder_ == null) {
          result.beingHitInfo_ = beingHitInfo_;
        } else {
          result.beingHitInfo_ = beingHitInfoBuilder_.build();
        }
        result.forwardType_ = forwardType_;
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
        if (other instanceof emu.grasscutter.net.proto.EvtBeingHitNotifyOuterClass.EvtBeingHitNotify) {
          return mergeFrom((emu.grasscutter.net.proto.EvtBeingHitNotifyOuterClass.EvtBeingHitNotify)other);
        } else {
          super.mergeFrom(other);
          return this;
        }
      }

      public Builder mergeFrom(emu.grasscutter.net.proto.EvtBeingHitNotifyOuterClass.EvtBeingHitNotify other) {
        if (other == emu.grasscutter.net.proto.EvtBeingHitNotifyOuterClass.EvtBeingHitNotify.getDefaultInstance()) return this;
        if (other.hasBeingHitInfo()) {
          mergeBeingHitInfo(other.getBeingHitInfo());
        }
        if (other.forwardType_ != 0) {
          setForwardTypeValue(other.getForwardTypeValue());
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
        emu.grasscutter.net.proto.EvtBeingHitNotifyOuterClass.EvtBeingHitNotify parsedMessage = null;
        try {
          parsedMessage = PARSER.parsePartialFrom(input, extensionRegistry);
        } catch (com.google.protobuf.InvalidProtocolBufferException e) {
          parsedMessage = (emu.grasscutter.net.proto.EvtBeingHitNotifyOuterClass.EvtBeingHitNotify) e.getUnfinishedMessage();
          throw e.unwrapIOException();
        } finally {
          if (parsedMessage != null) {
            mergeFrom(parsedMessage);
          }
        }
        return this;
      }

      private emu.grasscutter.net.proto.EvtBeingHitInfoOuterClass.EvtBeingHitInfo beingHitInfo_;
      private com.google.protobuf.SingleFieldBuilderV3<
          emu.grasscutter.net.proto.EvtBeingHitInfoOuterClass.EvtBeingHitInfo, emu.grasscutter.net.proto.EvtBeingHitInfoOuterClass.EvtBeingHitInfo.Builder, emu.grasscutter.net.proto.EvtBeingHitInfoOuterClass.EvtBeingHitInfoOrBuilder> beingHitInfoBuilder_;
      /**
       * <code>.EvtBeingHitInfo being_hit_info = 12;</code>
       * @return Whether the beingHitInfo field is set.
       */
      public boolean hasBeingHitInfo() {
        return beingHitInfoBuilder_ != null || beingHitInfo_ != null;
      }
      /**
       * <code>.EvtBeingHitInfo being_hit_info = 12;</code>
       * @return The beingHitInfo.
       */
      public emu.grasscutter.net.proto.EvtBeingHitInfoOuterClass.EvtBeingHitInfo getBeingHitInfo() {
        if (beingHitInfoBuilder_ == null) {
          return beingHitInfo_ == null ? emu.grasscutter.net.proto.EvtBeingHitInfoOuterClass.EvtBeingHitInfo.getDefaultInstance() : beingHitInfo_;
        } else {
          return beingHitInfoBuilder_.getMessage();
        }
      }
      /**
       * <code>.EvtBeingHitInfo being_hit_info = 12;</code>
       */
      public Builder setBeingHitInfo(emu.grasscutter.net.proto.EvtBeingHitInfoOuterClass.EvtBeingHitInfo value) {
        if (beingHitInfoBuilder_ == null) {
          if (value == null) {
            throw new NullPointerException();
          }
          beingHitInfo_ = value;
          onChanged();
        } else {
          beingHitInfoBuilder_.setMessage(value);
        }

        return this;
      }
      /**
       * <code>.EvtBeingHitInfo being_hit_info = 12;</code>
       */
      public Builder setBeingHitInfo(
          emu.grasscutter.net.proto.EvtBeingHitInfoOuterClass.EvtBeingHitInfo.Builder builderForValue) {
        if (beingHitInfoBuilder_ == null) {
          beingHitInfo_ = builderForValue.build();
          onChanged();
        } else {
          beingHitInfoBuilder_.setMessage(builderForValue.build());
        }

        return this;
      }
      /**
       * <code>.EvtBeingHitInfo being_hit_info = 12;</code>
       */
      public Builder mergeBeingHitInfo(emu.grasscutter.net.proto.EvtBeingHitInfoOuterClass.EvtBeingHitInfo value) {
        if (beingHitInfoBuilder_ == null) {
          if (beingHitInfo_ != null) {
            beingHitInfo_ =
              emu.grasscutter.net.proto.EvtBeingHitInfoOuterClass.EvtBeingHitInfo.newBuilder(beingHitInfo_).mergeFrom(value).buildPartial();
          } else {
            beingHitInfo_ = value;
          }
          onChanged();
        } else {
          beingHitInfoBuilder_.mergeFrom(value);
        }

        return this;
      }
      /**
       * <code>.EvtBeingHitInfo being_hit_info = 12;</code>
       */
      public Builder clearBeingHitInfo() {
        if (beingHitInfoBuilder_ == null) {
          beingHitInfo_ = null;
          onChanged();
        } else {
          beingHitInfo_ = null;
          beingHitInfoBuilder_ = null;
        }

        return this;
      }
      /**
       * <code>.EvtBeingHitInfo being_hit_info = 12;</code>
       */
      public emu.grasscutter.net.proto.EvtBeingHitInfoOuterClass.EvtBeingHitInfo.Builder getBeingHitInfoBuilder() {
        
        onChanged();
        return getBeingHitInfoFieldBuilder().getBuilder();
      }
      /**
       * <code>.EvtBeingHitInfo being_hit_info = 12;</code>
       */
      public emu.grasscutter.net.proto.EvtBeingHitInfoOuterClass.EvtBeingHitInfoOrBuilder getBeingHitInfoOrBuilder() {
        if (beingHitInfoBuilder_ != null) {
          return beingHitInfoBuilder_.getMessageOrBuilder();
        } else {
          return beingHitInfo_ == null ?
              emu.grasscutter.net.proto.EvtBeingHitInfoOuterClass.EvtBeingHitInfo.getDefaultInstance() : beingHitInfo_;
        }
      }
      /**
       * <code>.EvtBeingHitInfo being_hit_info = 12;</code>
       */
      private com.google.protobuf.SingleFieldBuilderV3<
          emu.grasscutter.net.proto.EvtBeingHitInfoOuterClass.EvtBeingHitInfo, emu.grasscutter.net.proto.EvtBeingHitInfoOuterClass.EvtBeingHitInfo.Builder, emu.grasscutter.net.proto.EvtBeingHitInfoOuterClass.EvtBeingHitInfoOrBuilder> 
          getBeingHitInfoFieldBuilder() {
        if (beingHitInfoBuilder_ == null) {
          beingHitInfoBuilder_ = new com.google.protobuf.SingleFieldBuilderV3<
              emu.grasscutter.net.proto.EvtBeingHitInfoOuterClass.EvtBeingHitInfo, emu.grasscutter.net.proto.EvtBeingHitInfoOuterClass.EvtBeingHitInfo.Builder, emu.grasscutter.net.proto.EvtBeingHitInfoOuterClass.EvtBeingHitInfoOrBuilder>(
                  getBeingHitInfo(),
                  getParentForChildren(),
                  isClean());
          beingHitInfo_ = null;
        }
        return beingHitInfoBuilder_;
      }

      private int forwardType_ = 0;
      /**
       * <code>.ForwardType forward_type = 11;</code>
       * @return The enum numeric value on the wire for forwardType.
       */
      @java.lang.Override public int getForwardTypeValue() {
        return forwardType_;
      }
      /**
       * <code>.ForwardType forward_type = 11;</code>
       * @param value The enum numeric value on the wire for forwardType to set.
       * @return This builder for chaining.
       */
      public Builder setForwardTypeValue(int value) {
        
        forwardType_ = value;
        onChanged();
        return this;
      }
      /**
       * <code>.ForwardType forward_type = 11;</code>
       * @return The forwardType.
       */
      @java.lang.Override
      public emu.grasscutter.net.proto.ForwardTypeOuterClass.ForwardType getForwardType() {
        @SuppressWarnings("deprecation")
        emu.grasscutter.net.proto.ForwardTypeOuterClass.ForwardType result = emu.grasscutter.net.proto.ForwardTypeOuterClass.ForwardType.valueOf(forwardType_);
        return result == null ? emu.grasscutter.net.proto.ForwardTypeOuterClass.ForwardType.UNRECOGNIZED : result;
      }
      /**
       * <code>.ForwardType forward_type = 11;</code>
       * @param value The forwardType to set.
       * @return This builder for chaining.
       */
      public Builder setForwardType(emu.grasscutter.net.proto.ForwardTypeOuterClass.ForwardType value) {
        if (value == null) {
          throw new NullPointerException();
        }
        
        forwardType_ = value.getNumber();
        onChanged();
        return this;
      }
      /**
       * <code>.ForwardType forward_type = 11;</code>
       * @return This builder for chaining.
       */
      public Builder clearForwardType() {
        
        forwardType_ = 0;
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


      // @@protoc_insertion_point(builder_scope:EvtBeingHitNotify)
    }

    // @@protoc_insertion_point(class_scope:EvtBeingHitNotify)
    private static final emu.grasscutter.net.proto.EvtBeingHitNotifyOuterClass.EvtBeingHitNotify DEFAULT_INSTANCE;
    static {
      DEFAULT_INSTANCE = new emu.grasscutter.net.proto.EvtBeingHitNotifyOuterClass.EvtBeingHitNotify();
    }

    public static emu.grasscutter.net.proto.EvtBeingHitNotifyOuterClass.EvtBeingHitNotify getDefaultInstance() {
      return DEFAULT_INSTANCE;
    }

    private static final com.google.protobuf.Parser<EvtBeingHitNotify>
        PARSER = new com.google.protobuf.AbstractParser<EvtBeingHitNotify>() {
      @java.lang.Override
      public EvtBeingHitNotify parsePartialFrom(
          com.google.protobuf.CodedInputStream input,
          com.google.protobuf.ExtensionRegistryLite extensionRegistry)
          throws com.google.protobuf.InvalidProtocolBufferException {
        return new EvtBeingHitNotify(input, extensionRegistry);
      }
    };

    public static com.google.protobuf.Parser<EvtBeingHitNotify> parser() {
      return PARSER;
    }

    @java.lang.Override
    public com.google.protobuf.Parser<EvtBeingHitNotify> getParserForType() {
      return PARSER;
    }

    @java.lang.Override
    public emu.grasscutter.net.proto.EvtBeingHitNotifyOuterClass.EvtBeingHitNotify getDefaultInstanceForType() {
      return DEFAULT_INSTANCE;
    }

  }

  private static final com.google.protobuf.Descriptors.Descriptor
    internal_static_EvtBeingHitNotify_descriptor;
  private static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_EvtBeingHitNotify_fieldAccessorTable;

  public static com.google.protobuf.Descriptors.FileDescriptor
      getDescriptor() {
    return descriptor;
  }
  private static  com.google.protobuf.Descriptors.FileDescriptor
      descriptor;
  static {
    java.lang.String[] descriptorData = {
      "\n\027EvtBeingHitNotify.proto\032\025EvtBeingHitIn" +
      "fo.proto\032\021ForwardType.proto\"a\n\021EvtBeingH" +
      "itNotify\022(\n\016being_hit_info\030\014 \001(\0132\020.EvtBe" +
      "ingHitInfo\022\"\n\014forward_type\030\013 \001(\0162\014.Forwa" +
      "rdTypeB\033\n\031emu.grasscutter.net.protob\006pro" +
      "to3"
    };
    descriptor = com.google.protobuf.Descriptors.FileDescriptor
      .internalBuildGeneratedFileFrom(descriptorData,
        new com.google.protobuf.Descriptors.FileDescriptor[] {
          emu.grasscutter.net.proto.EvtBeingHitInfoOuterClass.getDescriptor(),
          emu.grasscutter.net.proto.ForwardTypeOuterClass.getDescriptor(),
        });
    internal_static_EvtBeingHitNotify_descriptor =
      getDescriptor().getMessageTypes().get(0);
    internal_static_EvtBeingHitNotify_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_EvtBeingHitNotify_descriptor,
        new java.lang.String[] { "BeingHitInfo", "ForwardType", });
    emu.grasscutter.net.proto.EvtBeingHitInfoOuterClass.getDescriptor();
    emu.grasscutter.net.proto.ForwardTypeOuterClass.getDescriptor();
  }

  // @@protoc_insertion_point(outer_class_scope)
}
