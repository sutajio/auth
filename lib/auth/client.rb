module Auth
  class Client
    def initialize(attributes)
      @attributes = attributes
    end

    def method_missing(method)
      @attributes[method.to_s] || @attributes[method.to_sym]
    end
  end
end
