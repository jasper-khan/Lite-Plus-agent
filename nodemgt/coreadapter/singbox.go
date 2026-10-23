package coreadapter

func NewSingBox() Core {
	if linkedSingBox != nil {
		return linkedSingBox()
	}
	return newNative("sing-box", SingBoxVersion, false)
}

var linkedSingBox func() Core
