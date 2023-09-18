// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: DHKMFNNAKIA.proto

package emu.grasscutter.net.proto;

public final class DHKMFNNAKIAOuterClass {
  private DHKMFNNAKIAOuterClass() {}
  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistryLite registry) {
  }

  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistry registry) {
    registerAllExtensions(
        (com.google.protobuf.ExtensionRegistryLite) registry);
  }
  public interface DHKMFNNAKIAOrBuilder extends
      // @@protoc_insertion_point(interface_extends:DHKMFNNAKIA)
      com.google.protobuf.MessageOrBuilder {

    /**
     * <code>uint32 cost_time = 6;</code>
     * @return The costTime.
     */
    int getCostTime();

    /**
     * <code>bool is_new_record = 1;</code>
     * @return The isNewRecord.
     */
    boolean getIsNewRecord();

    /**
     * <code>uint32 level_id = 9;</code>
     * @return The levelId.
     */
    int getLevelId();

    /**
     * <code>uint32 score = 15;</code>
     * @return The score.
     */
    int getScore();

    /**
     * <code>bool NPPPCDAPHPP = 2;</code>
     * @return The nPPPCDAPHPP.
     */
    boolean getNPPPCDAPHPP();

    /**
     * <code>bool is_succ = 14;</code>
     * @return The isSucc.
     */
    boolean getIsSucc();
  }
  /**
   * <pre>
   * CmdId: 23308
   * </pre>
   *
   * Protobuf type {@code DHKMFNNAKIA}
   */
  public static final class DHKMFNNAKIA extends
      com.google.protobuf.GeneratedMessageV3 implements
      // @@protoc_insertion_point(message_implements:DHKMFNNAKIA)
      DHKMFNNAKIAOrBuilder {
  private static final long serialVersionUID = 0L;
    // Use DHKMFNNAKIA.newBuilder() to construct.
    private DHKMFNNAKIA(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
      super(builder);
    }
    private DHKMFNNAKIA() {
    }

    @java.lang.Override
    @SuppressWarnings({"unused"})
    protected java.lang.Object newInstance(
        UnusedPrivateParameter unused) {
      return new DHKMFNNAKIA();
    }

    @java.lang.Override
    public final com.google.protobuf.UnknownFieldSet
    getUnknownFields() {
      return this.unknownFields;
    }
    private DHKMFNNAKIA(
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
            case 8: {

              isNewRecord_ = input.readBool();
              break;
            }
            case 16: {

              nPPPCDAPHPP_ = input.readBool();
              break;
            }
            case 48: {

              costTime_ = input.readUInt32();
              break;
            }
            case 72: {

              levelId_ = input.readUInt32();
              break;
            }
            case 112: {

              isSucc_ = input.readBool();
              break;
            }
            case 120: {

              score_ = input.readUInt32();
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
      return emu.grasscutter.net.proto.DHKMFNNAKIAOuterClass.internal_static_DHKMFNNAKIA_descriptor;
    }

    @java.lang.Override
    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return emu.grasscutter.net.proto.DHKMFNNAKIAOuterClass.internal_static_DHKMFNNAKIA_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              emu.grasscutter.net.proto.DHKMFNNAKIAOuterClass.DHKMFNNAKIA.class, emu.grasscutter.net.proto.DHKMFNNAKIAOuterClass.DHKMFNNAKIA.Builder.class);
    }

    public static final int COST_TIME_FIELD_NUMBER = 6;
    private int costTime_;
    /**
     * <code>uint32 cost_time = 6;</code>
     * @return The costTime.
     */
    @java.lang.Override
    public int getCostTime() {
      return costTime_;
    }

    public static final int IS_NEW_RECORD_FIELD_NUMBER = 1;
    private boolean isNewRecord_;
    /**
     * <code>bool is_new_record = 1;</code>
     * @return The isNewRecord.
     */
    @java.lang.Override
    public boolean getIsNewRecord() {
      return isNewRecord_;
    }

    public static final int LEVEL_ID_FIELD_NUMBER = 9;
    private int levelId_;
    /**
     * <code>uint32 level_id = 9;</code>
     * @return The levelId.
     */
    @java.lang.Override
    public int getLevelId() {
      return levelId_;
    }

    public static final int SCORE_FIELD_NUMBER = 15;
    private int score_;
    /**
     * <code>uint32 score = 15;</code>
     * @return The score.
     */
    @java.lang.Override
    public int getScore() {
      return score_;
    }

    public static final int NPPPCDAPHPP_FIELD_NUMBER = 2;
    private boolean nPPPCDAPHPP_;
    /**
     * <code>bool NPPPCDAPHPP = 2;</code>
     * @return The nPPPCDAPHPP.
     */
    @java.lang.Override
    public boolean getNPPPCDAPHPP() {
      return nPPPCDAPHPP_;
    }

    public static final int IS_SUCC_FIELD_NUMBER = 14;
    private boolean isSucc_;
    /**
     * <code>bool is_succ = 14;</code>
     * @return The isSucc.
     */
    @java.lang.Override
    public boolean getIsSucc() {
      return isSucc_;
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
      if (isNewRecord_ != false) {
        output.writeBool(1, isNewRecord_);
      }
      if (nPPPCDAPHPP_ != false) {
        output.writeBool(2, nPPPCDAPHPP_);
      }
      if (costTime_ != 0) {
        output.writeUInt32(6, costTime_);
      }
      if (levelId_ != 0) {
        output.writeUInt32(9, levelId_);
      }
      if (isSucc_ != false) {
        output.writeBool(14, isSucc_);
      }
      if (score_ != 0) {
        output.writeUInt32(15, score_);
      }
      unknownFields.writeTo(output);
    }

    @java.lang.Override
    public int getSerializedSize() {
      int size = memoizedSize;
      if (size != -1) return size;

      size = 0;
      if (isNewRecord_ != false) {
        size += com.google.protobuf.CodedOutputStream
          .computeBoolSize(1, isNewRecord_);
      }
      if (nPPPCDAPHPP_ != false) {
        size += com.google.protobuf.CodedOutputStream
          .computeBoolSize(2, nPPPCDAPHPP_);
      }
      if (costTime_ != 0) {
        size += com.google.protobuf.CodedOutputStream
          .computeUInt32Size(6, costTime_);
      }
      if (levelId_ != 0) {
        size += com.google.protobuf.CodedOutputStream
          .computeUInt32Size(9, levelId_);
      }
      if (isSucc_ != false) {
        size += com.google.protobuf.CodedOutputStream
          .computeBoolSize(14, isSucc_);
      }
      if (score_ != 0) {
        size += com.google.protobuf.CodedOutputStream
          .computeUInt32Size(15, score_);
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
      if (!(obj instanceof emu.grasscutter.net.proto.DHKMFNNAKIAOuterClass.DHKMFNNAKIA)) {
        return super.equals(obj);
      }
      emu.grasscutter.net.proto.DHKMFNNAKIAOuterClass.DHKMFNNAKIA other = (emu.grasscutter.net.proto.DHKMFNNAKIAOuterClass.DHKMFNNAKIA) obj;

      if (getCostTime()
          != other.getCostTime()) return false;
      if (getIsNewRecord()
          != other.getIsNewRecord()) return false;
      if (getLevelId()
          != other.getLevelId()) return false;
      if (getScore()
          != other.getScore()) return false;
      if (getNPPPCDAPHPP()
          != other.getNPPPCDAPHPP()) return false;
      if (getIsSucc()
          != other.getIsSucc()) return false;
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
      hash = (37 * hash) + COST_TIME_FIELD_NUMBER;
      hash = (53 * hash) + getCostTime();
      hash = (37 * hash) + IS_NEW_RECORD_FIELD_NUMBER;
      hash = (53 * hash) + com.google.protobuf.Internal.hashBoolean(
          getIsNewRecord());
      hash = (37 * hash) + LEVEL_ID_FIELD_NUMBER;
      hash = (53 * hash) + getLevelId();
      hash = (37 * hash) + SCORE_FIELD_NUMBER;
      hash = (53 * hash) + getScore();
      hash = (37 * hash) + NPPPCDAPHPP_FIELD_NUMBER;
      hash = (53 * hash) + com.google.protobuf.Internal.hashBoolean(
          getNPPPCDAPHPP());
      hash = (37 * hash) + IS_SUCC_FIELD_NUMBER;
      hash = (53 * hash) + com.google.protobuf.Internal.hashBoolean(
          getIsSucc());
      hash = (29 * hash) + unknownFields.hashCode();
      memoizedHashCode = hash;
      return hash;
    }

    public static emu.grasscutter.net.proto.DHKMFNNAKIAOuterClass.DHKMFNNAKIA parseFrom(
        java.nio.ByteBuffer data)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data);
    }
    public static emu.grasscutter.net.proto.DHKMFNNAKIAOuterClass.DHKMFNNAKIA parseFrom(
        java.nio.ByteBuffer data,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data, extensionRegistry);
    }
    public static emu.grasscutter.net.proto.DHKMFNNAKIAOuterClass.DHKMFNNAKIA parseFrom(
        com.google.protobuf.ByteString data)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data);
    }
    public static emu.grasscutter.net.proto.DHKMFNNAKIAOuterClass.DHKMFNNAKIA parseFrom(
        com.google.protobuf.ByteString data,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data, extensionRegistry);
    }
    public static emu.grasscutter.net.proto.DHKMFNNAKIAOuterClass.DHKMFNNAKIA parseFrom(byte[] data)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data);
    }
    public static emu.grasscutter.net.proto.DHKMFNNAKIAOuterClass.DHKMFNNAKIA parseFrom(
        byte[] data,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data, extensionRegistry);
    }
    public static emu.grasscutter.net.proto.DHKMFNNAKIAOuterClass.DHKMFNNAKIA parseFrom(java.io.InputStream input)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseWithIOException(PARSER, input);
    }
    public static emu.grasscutter.net.proto.DHKMFNNAKIAOuterClass.DHKMFNNAKIA parseFrom(
        java.io.InputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseWithIOException(PARSER, input, extensionRegistry);
    }
    public static emu.grasscutter.net.proto.DHKMFNNAKIAOuterClass.DHKMFNNAKIA parseDelimitedFrom(java.io.InputStream input)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseDelimitedWithIOException(PARSER, input);
    }
    public static emu.grasscutter.net.proto.DHKMFNNAKIAOuterClass.DHKMFNNAKIA parseDelimitedFrom(
        java.io.InputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
    }
    public static emu.grasscutter.net.proto.DHKMFNNAKIAOuterClass.DHKMFNNAKIA parseFrom(
        com.google.protobuf.CodedInputStream input)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseWithIOException(PARSER, input);
    }
    public static emu.grasscutter.net.proto.DHKMFNNAKIAOuterClass.DHKMFNNAKIA parseFrom(
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
    public static Builder newBuilder(emu.grasscutter.net.proto.DHKMFNNAKIAOuterClass.DHKMFNNAKIA prototype) {
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
     * CmdId: 23308
     * </pre>
     *
     * Protobuf type {@code DHKMFNNAKIA}
     */
    public static final class Builder extends
        com.google.protobuf.GeneratedMessageV3.Builder<Builder> implements
        // @@protoc_insertion_point(builder_implements:DHKMFNNAKIA)
        emu.grasscutter.net.proto.DHKMFNNAKIAOuterClass.DHKMFNNAKIAOrBuilder {
      public static final com.google.protobuf.Descriptors.Descriptor
          getDescriptor() {
        return emu.grasscutter.net.proto.DHKMFNNAKIAOuterClass.internal_static_DHKMFNNAKIA_descriptor;
      }

      @java.lang.Override
      protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
          internalGetFieldAccessorTable() {
        return emu.grasscutter.net.proto.DHKMFNNAKIAOuterClass.internal_static_DHKMFNNAKIA_fieldAccessorTable
            .ensureFieldAccessorsInitialized(
                emu.grasscutter.net.proto.DHKMFNNAKIAOuterClass.DHKMFNNAKIA.class, emu.grasscutter.net.proto.DHKMFNNAKIAOuterClass.DHKMFNNAKIA.Builder.class);
      }

      // Construct using emu.grasscutter.net.proto.DHKMFNNAKIAOuterClass.DHKMFNNAKIA.newBuilder()
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
        costTime_ = 0;

        isNewRecord_ = false;

        levelId_ = 0;

        score_ = 0;

        nPPPCDAPHPP_ = false;

        isSucc_ = false;

        return this;
      }

      @java.lang.Override
      public com.google.protobuf.Descriptors.Descriptor
          getDescriptorForType() {
        return emu.grasscutter.net.proto.DHKMFNNAKIAOuterClass.internal_static_DHKMFNNAKIA_descriptor;
      }

      @java.lang.Override
      public emu.grasscutter.net.proto.DHKMFNNAKIAOuterClass.DHKMFNNAKIA getDefaultInstanceForType() {
        return emu.grasscutter.net.proto.DHKMFNNAKIAOuterClass.DHKMFNNAKIA.getDefaultInstance();
      }

      @java.lang.Override
      public emu.grasscutter.net.proto.DHKMFNNAKIAOuterClass.DHKMFNNAKIA build() {
        emu.grasscutter.net.proto.DHKMFNNAKIAOuterClass.DHKMFNNAKIA result = buildPartial();
        if (!result.isInitialized()) {
          throw newUninitializedMessageException(result);
        }
        return result;
      }

      @java.lang.Override
      public emu.grasscutter.net.proto.DHKMFNNAKIAOuterClass.DHKMFNNAKIA buildPartial() {
        emu.grasscutter.net.proto.DHKMFNNAKIAOuterClass.DHKMFNNAKIA result = new emu.grasscutter.net.proto.DHKMFNNAKIAOuterClass.DHKMFNNAKIA(this);
        result.costTime_ = costTime_;
        result.isNewRecord_ = isNewRecord_;
        result.levelId_ = levelId_;
        result.score_ = score_;
        result.nPPPCDAPHPP_ = nPPPCDAPHPP_;
        result.isSucc_ = isSucc_;
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
        if (other instanceof emu.grasscutter.net.proto.DHKMFNNAKIAOuterClass.DHKMFNNAKIA) {
          return mergeFrom((emu.grasscutter.net.proto.DHKMFNNAKIAOuterClass.DHKMFNNAKIA)other);
        } else {
          super.mergeFrom(other);
          return this;
        }
      }

      public Builder mergeFrom(emu.grasscutter.net.proto.DHKMFNNAKIAOuterClass.DHKMFNNAKIA other) {
        if (other == emu.grasscutter.net.proto.DHKMFNNAKIAOuterClass.DHKMFNNAKIA.getDefaultInstance()) return this;
        if (other.getCostTime() != 0) {
          setCostTime(other.getCostTime());
        }
        if (other.getIsNewRecord() != false) {
          setIsNewRecord(other.getIsNewRecord());
        }
        if (other.getLevelId() != 0) {
          setLevelId(other.getLevelId());
        }
        if (other.getScore() != 0) {
          setScore(other.getScore());
        }
        if (other.getNPPPCDAPHPP() != false) {
          setNPPPCDAPHPP(other.getNPPPCDAPHPP());
        }
        if (other.getIsSucc() != false) {
          setIsSucc(other.getIsSucc());
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
        emu.grasscutter.net.proto.DHKMFNNAKIAOuterClass.DHKMFNNAKIA parsedMessage = null;
        try {
          parsedMessage = PARSER.parsePartialFrom(input, extensionRegistry);
        } catch (com.google.protobuf.InvalidProtocolBufferException e) {
          parsedMessage = (emu.grasscutter.net.proto.DHKMFNNAKIAOuterClass.DHKMFNNAKIA) e.getUnfinishedMessage();
          throw e.unwrapIOException();
        } finally {
          if (parsedMessage != null) {
            mergeFrom(parsedMessage);
          }
        }
        return this;
      }

      private int costTime_ ;
      /**
       * <code>uint32 cost_time = 6;</code>
       * @return The costTime.
       */
      @java.lang.Override
      public int getCostTime() {
        return costTime_;
      }
      /**
       * <code>uint32 cost_time = 6;</code>
       * @param value The costTime to set.
       * @return This builder for chaining.
       */
      public Builder setCostTime(int value) {
        
        costTime_ = value;
        onChanged();
        return this;
      }
      /**
       * <code>uint32 cost_time = 6;</code>
       * @return This builder for chaining.
       */
      public Builder clearCostTime() {
        
        costTime_ = 0;
        onChanged();
        return this;
      }

      private boolean isNewRecord_ ;
      /**
       * <code>bool is_new_record = 1;</code>
       * @return The isNewRecord.
       */
      @java.lang.Override
      public boolean getIsNewRecord() {
        return isNewRecord_;
      }
      /**
       * <code>bool is_new_record = 1;</code>
       * @param value The isNewRecord to set.
       * @return This builder for chaining.
       */
      public Builder setIsNewRecord(boolean value) {
        
        isNewRecord_ = value;
        onChanged();
        return this;
      }
      /**
       * <code>bool is_new_record = 1;</code>
       * @return This builder for chaining.
       */
      public Builder clearIsNewRecord() {
        
        isNewRecord_ = false;
        onChanged();
        return this;
      }

      private int levelId_ ;
      /**
       * <code>uint32 level_id = 9;</code>
       * @return The levelId.
       */
      @java.lang.Override
      public int getLevelId() {
        return levelId_;
      }
      /**
       * <code>uint32 level_id = 9;</code>
       * @param value The levelId to set.
       * @return This builder for chaining.
       */
      public Builder setLevelId(int value) {
        
        levelId_ = value;
        onChanged();
        return this;
      }
      /**
       * <code>uint32 level_id = 9;</code>
       * @return This builder for chaining.
       */
      public Builder clearLevelId() {
        
        levelId_ = 0;
        onChanged();
        return this;
      }

      private int score_ ;
      /**
       * <code>uint32 score = 15;</code>
       * @return The score.
       */
      @java.lang.Override
      public int getScore() {
        return score_;
      }
      /**
       * <code>uint32 score = 15;</code>
       * @param value The score to set.
       * @return This builder for chaining.
       */
      public Builder setScore(int value) {
        
        score_ = value;
        onChanged();
        return this;
      }
      /**
       * <code>uint32 score = 15;</code>
       * @return This builder for chaining.
       */
      public Builder clearScore() {
        
        score_ = 0;
        onChanged();
        return this;
      }

      private boolean nPPPCDAPHPP_ ;
      /**
       * <code>bool NPPPCDAPHPP = 2;</code>
       * @return The nPPPCDAPHPP.
       */
      @java.lang.Override
      public boolean getNPPPCDAPHPP() {
        return nPPPCDAPHPP_;
      }
      /**
       * <code>bool NPPPCDAPHPP = 2;</code>
       * @param value The nPPPCDAPHPP to set.
       * @return This builder for chaining.
       */
      public Builder setNPPPCDAPHPP(boolean value) {
        
        nPPPCDAPHPP_ = value;
        onChanged();
        return this;
      }
      /**
       * <code>bool NPPPCDAPHPP = 2;</code>
       * @return This builder for chaining.
       */
      public Builder clearNPPPCDAPHPP() {
        
        nPPPCDAPHPP_ = false;
        onChanged();
        return this;
      }

      private boolean isSucc_ ;
      /**
       * <code>bool is_succ = 14;</code>
       * @return The isSucc.
       */
      @java.lang.Override
      public boolean getIsSucc() {
        return isSucc_;
      }
      /**
       * <code>bool is_succ = 14;</code>
       * @param value The isSucc to set.
       * @return This builder for chaining.
       */
      public Builder setIsSucc(boolean value) {
        
        isSucc_ = value;
        onChanged();
        return this;
      }
      /**
       * <code>bool is_succ = 14;</code>
       * @return This builder for chaining.
       */
      public Builder clearIsSucc() {
        
        isSucc_ = false;
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


      // @@protoc_insertion_point(builder_scope:DHKMFNNAKIA)
    }

    // @@protoc_insertion_point(class_scope:DHKMFNNAKIA)
    private static final emu.grasscutter.net.proto.DHKMFNNAKIAOuterClass.DHKMFNNAKIA DEFAULT_INSTANCE;
    static {
      DEFAULT_INSTANCE = new emu.grasscutter.net.proto.DHKMFNNAKIAOuterClass.DHKMFNNAKIA();
    }

    public static emu.grasscutter.net.proto.DHKMFNNAKIAOuterClass.DHKMFNNAKIA getDefaultInstance() {
      return DEFAULT_INSTANCE;
    }

    private static final com.google.protobuf.Parser<DHKMFNNAKIA>
        PARSER = new com.google.protobuf.AbstractParser<DHKMFNNAKIA>() {
      @java.lang.Override
      public DHKMFNNAKIA parsePartialFrom(
          com.google.protobuf.CodedInputStream input,
          com.google.protobuf.ExtensionRegistryLite extensionRegistry)
          throws com.google.protobuf.InvalidProtocolBufferException {
        return new DHKMFNNAKIA(input, extensionRegistry);
      }
    };

    public static com.google.protobuf.Parser<DHKMFNNAKIA> parser() {
      return PARSER;
    }

    @java.lang.Override
    public com.google.protobuf.Parser<DHKMFNNAKIA> getParserForType() {
      return PARSER;
    }

    @java.lang.Override
    public emu.grasscutter.net.proto.DHKMFNNAKIAOuterClass.DHKMFNNAKIA getDefaultInstanceForType() {
      return DEFAULT_INSTANCE;
    }

  }

  private static final com.google.protobuf.Descriptors.Descriptor
    internal_static_DHKMFNNAKIA_descriptor;
  private static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_DHKMFNNAKIA_fieldAccessorTable;

  public static com.google.protobuf.Descriptors.FileDescriptor
      getDescriptor() {
    return descriptor;
  }
  private static  com.google.protobuf.Descriptors.FileDescriptor
      descriptor;
  static {
    java.lang.String[] descriptorData = {
      "\n\021DHKMFNNAKIA.proto\"~\n\013DHKMFNNAKIA\022\021\n\tco" +
      "st_time\030\006 \001(\r\022\025\n\ris_new_record\030\001 \001(\010\022\020\n\010" +
      "level_id\030\t \001(\r\022\r\n\005score\030\017 \001(\r\022\023\n\013NPPPCDA" +
      "PHPP\030\002 \001(\010\022\017\n\007is_succ\030\016 \001(\010B\033\n\031emu.grass" +
      "cutter.net.protob\006proto3"
    };
    descriptor = com.google.protobuf.Descriptors.FileDescriptor
      .internalBuildGeneratedFileFrom(descriptorData,
        new com.google.protobuf.Descriptors.FileDescriptor[] {
        });
    internal_static_DHKMFNNAKIA_descriptor =
      getDescriptor().getMessageTypes().get(0);
    internal_static_DHKMFNNAKIA_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_DHKMFNNAKIA_descriptor,
        new java.lang.String[] { "CostTime", "IsNewRecord", "LevelId", "Score", "NPPPCDAPHPP", "IsSucc", });
  }

  // @@protoc_insertion_point(outer_class_scope)
}